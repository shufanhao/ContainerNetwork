## 1. What is Contiv
思科开源的容器网络方案，是一个用于跨虚拟机、裸机、公有云或私有云的异构容器部署的开源容器网络架构，并与主流容器编排系统集成。
Contiv最主要的优势是直接提供了多租户网络，可以通过设置不同的租户，隔离网络。
支持两种网络模式：
L2 VLAN Bridged，基于OVS的二层交换
L3 Routed network, e.g. vxlan, BGP, ACI
Network Policy，如Bandwidth, Isolation等, 基于openflow table的访问控制

Contiv: https://contiv.io/documents/gettingStarted/

## 2. How it work 
### 2.1 Contiv 主要组件
架构图如下：
![image](https://github.com/shufanhao/ContainerNetwork/blob/master/image/cni/contiv-arch.png)

1. Netmaster。对外提供REST API; 学习路由并分发给Netplugin nodes; 负责IP, VLAN, VXLAN ID等资源的分发； 用分布式的key/value DB，如：etcd,consul去保存contiv所有数据。因此，它是无状态的，可扩展的，支持restart。并且Netmaster集成了心跳机制，避免了单点故障。
2. Netplugin。在worker节点上运行netplugin，它实现CNI/CNM 网络插件，可以适用于k8s/Docker Swarm。通过REST API和Netmaster进行通信。Netplugin 后台进程作为每个宿主机上的 Agent 与 Docker 及 OVS 通信，处理来自 Docker 的请求，管理 OVS。Docker 方面接口为 remote driver，包括一系列 Docker 定义的 JSON-RPC(POST) 消息。OVS 方面接口为 remote ovsdb，也是 JSON-RPC 消息。以上消息都在 localhost 上处理。
3. contiv UI/netctl, contiv即提供web UI 让用户管理网络，又提供netctl的命令行工具去创建网络，实际上还是与netmaster提供的rest api 接口进行交互。
## 3. CCE 集群搭建 Contiv和分析
### 3.1 前提条件
已经搭建好CCE集群。如下是我的work节点环境, cluster id: c-Hbnqchw5。
- instance-1: 192.168.0.24
- instance-2: 192.168.0.25
### 3.2 修改CCE默认配置
因为CCE上的k8s集群是用云服务商提供的在VPC上配置路由的方法，实现POD间跨节点通信的，所以如果用contiv，需要将这种方式换掉。

在master节点，停止kube-cloud-controller
```
service kube-cloud-controller stop
```
这一步和之前搭建calico、flannel有些不同，这一步在创建好netmaster/netplugin之后再去执行（碰到坑，先执行的话，等到创建好netmaster, netplugin之后发现node是not ready状态）修改work节点的kubelet启动参数。将原来的cloud-provide，cloud-config 参数去掉，network-plugin=kubenet 修改为cni。修改之后，示例如下。并且记录下容器网络ip, 可以从下面参数中取到：non-masquerade-cidr。其他关于CNI的配置参数，用默认值即可。


```
[root@instance-uf0hnfr5-1 ~]# cat /etc/systemd/system/kubelet.service
[Unit]
Description=Kubernetes Kubelet
After=docker.service
Requires=docker.service

[Service]
ExecStart=/opt/kube/bin/kubelet \
--address=192.168.0.5 \
--allow-privileged=true \
--client-ca-file=/etc/kubernetes/pki/ca.pem \
--cluster-dns=172.18.0.10 \
--cluster-domain=cluster.local \
--docker-root=/data/docker \
--fail-swap-on=false \
--feature-gates=DevicePlugins=true,RotateKubeletServerCertificate=true,MountPropagation=true,CSIPersistentVolume=true \
--hostname-override=192.168.0.5 \
--kubeconfig=/etc/kubernetes/kubelet.conf \
--logtostderr=true \
--network-plugin=cni \
--non-masquerade-cidr=172.16.0.0/16 \
--pod-infra-container-image=hub-readonly.baidubce.com/public/pause:2.0 \
--pod-manifest-path=/etc/kubernetes/manifests \
--root-dir=/data/kubelet \
--tls-cipher-suites=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,TLS_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_256_CBC_SHA,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA \
--anonymous-auth=false \
--v=4 \
--enforce-node-allocatable=pods \
--eviction-hard=memory.available<5%,nodefs.available<10%,imagefs.available<10%% \
--eviction-soft=memory.available<10%,nodefs.available<15%,imagefs.available<15%% \
--eviction-soft-grace-period=memory.available=2m,nodefs.available=2m,imagefs.available=2m \
--eviction-max-pod-grace-period=30 \
--eviction-minimum-reclaim=memory.available=0Mi,nodefs.available=500Mi,imagefs.available=500Mi

Restart=always
Type=simple
LimitNOFILE=65536
```
然后执行下面命令，重启kubelet 服务
```
systemctl daemon-reload
service kubelet restart
```
### 3.3 创建Contiv
Refer: https://github.com/contiv/install

用最新版的1.1.9 版本发现有问题，装不了，启动netplugin的时候会报错, 只好用1.1.8版本。 https://github.com/contiv/install/releases/download/1.1.8/contiv-1.1.8.tgz
现在下来后解压即可，然后执行如下，-n 后面是netmaster的地址


```
[root@instance-ra68ebjl-1 contiv-1.1.8]# sh ./install/k8s/install.sh -n 192.168.0.24
Installing Contiv for Kubernetes
secret "aci.key" deleted
secret/aci.key created
Generating local certs for Contiv Proxy
Setting installation parameters
Applying contiv installation
To customize the installation press Ctrl+C and edit ./.contiv.yaml.
```
生成出的.contiv.yaml是不能直接用的，因为默认是netmaster只能调度到master节点上，要修改下，修改后的contiv.yaml


```
[root@instance-ra68ebjl-1]# kubectl apply -f contiv.yaml
clusterrolebinding.rbac.authorization.k8s.io/contiv-netplugin configured
clusterrole.rbac.authorization.k8s.io/contiv-netplugin configured
serviceaccount/contiv-netplugin unchanged
clusterrolebinding.rbac.authorization.k8s.io/contiv-netmaster configured
clusterrole.rbac.authorization.k8s.io/contiv-netmaster configured
serviceaccount/contiv-netmaster unchanged
configmap/contiv-config unchanged
daemonset.extensions/contiv-netplugin configured
replicaset.extensions/contiv-netmaster configured
```
然后确保netmaster, netplugin 都正常启动即可。有个坑 要在worker节点上执行下下面的命令否则netplugin启动不成功
```
sudo modprobe openvswitch # refer:https://github.com/contiv/netplugin/issues/978
```
worker节点安装netctl：
```
c_id=$(docker create --name netplugin-tmp contiv/netplugin:1.1.8)
docker cp ${c_id}:/contiv/bin/netctl /usr/bin
docker rm ${c_id}
```
验证UI是否可以登录：https://106.12.40.134:10000/#/login, admin/admin

至此，已经完成CCE上搭建contiv的过程。

### 3.4 Contiv 分析
完成3.3之后，只是contiv的组件已经成功创建出来，但是如果要让创建的pod能相互ping通，还需要自己通过UI或者netctl创建网络。如下是global info，forward mode是bridge也就是L2的OVS方式。


```
[root@instance-ra68ebjl-1 ~]# netctl global info
Fabric mode: default
Forward mode: bridge
ARP mode: proxy
Vlan Range: 1-4094
Vxlan range: 1-10000
Private subnet: 172.19.0.0/16
```
通过下面命令可以看到默认的配置。Contiv下的pod是通过label的方式匹配到不同的network和tenant，如果匹配不上会用default的network和Tenant。
```
[root@instance-ra68ebjl-1 ~]# netctl net ls -a
Tenant   Network      Nw Type  Encap type  Packet tag  Subnet         Gateway     IPv6Subnet  IPv6Gateway  Cfgd Tag
------   -------      -------  ----------  ----------  -------        ------      ----------  -----------  ---------
default  default-net  data     vlan        0           172.20.0.0/22  172.20.0.1
```

#### 3.4.1 创建基本网络
创建的网络默认是绑定的默认租户


```
[root@instance-ra68ebjl-1 ~]# netctl net create --subnet=10.1.2.0/24 --gateway=10.1.2.1 contiv-net
Creating network default:contiv-net
[root@instance-ra68ebjl-1 ~]# netctl net ls
Tenant   Network     Nw Type  Encap type  Packet tag  Subnet       Gateway   IPv6Subnet  IPv6Gateway  Cfgd Tag
------   -------     -------  ----------  ----------  -------      ------    ----------  -----------  ---------
default  contiv-net  data     vxlan       0           10.1.2.0/24  10.1.2.1
```

部署nginx, 注意添加的label,  io.contiv.tenant: default  和 io.contiv.network: contiv-net


```
---
apiVersion: extensions/v1beta1
kind: Deployment
metadata:
  name: nginx
  labels:
    app: nginx
spec:
  replicas: 3
  selector:
    matchLabels:
      app: nginx
  template:
    metadata:
      labels:
        app: nginx
        io.contiv.tenant: default
        io.contiv.network: contiv-net
    spec:
      containers:
      - name: nginx
        image: hub.baidubce.com/cce/nginx-alpine-go:latest
        ports:
        - containerPort: 80


[root@instance-ra68ebjl-1 backup]# kubectl get pods -o wide --all-namespaces
NAMESPACE NAME READY STATUS RESTARTS AGE IP NODE NOMINATED NODE
default nginx-575f45f977-4cfp8 1/1 Running 0 4s 10.1.2.4 192.168.0.24 <none>
default nginx-575f45f977-rmh76 1/1 Running 0 4s 10.1.2.6 192.168.0.25 <none>
default nginx-575f45f977-wvm7z 1/1 Running 0 4s 10.1.2.5 192.168.0.25 <none>
```

在其中一个nginx上可以ping通另一个节点的nginx，只有一跳。为什么呢 ？是不是只是二层的一个转发 ？应该是的因为通过ip route命令都没有看到容器网段的路由。还有一点和flannel, contiv的区别，不同节点上的容器网络的网络地址都是一样的，不像flannel, calico的不同节点的容器网络的网络地址是不同的，这样的好处可以节约大量ip地址。


```
[root@instance-ra68ebjl-1 backup]# kubectl exec -it nginx-575f45f977-4cfp8 /bin/sh
 # traceroute 10.1.2.6 -n
traceroute to 10.1.2.6 (10.1.2.6), 30 hops max, 46 byte packets
 1  10.1.2.6  0.524 ms  0.436 ms  0.341 ms
3.4.2 创建另一个tenant


[root@instance-ra68ebjl-1 ~]# netctl tenant create blue
Creating tenant: blue
[root@instance-ra68ebjl-1 ~]# netctl net create -t blue --subnet=10.1.2.0/24 -g 10.1.2.1 contiv-net
Creating network blue:contiv-net
[root@instance-ra68ebjl-1 ~]#  netctl net ls -t blue
Tenant  Network     Nw Type  Encap type  Packet tag  Subnet       Gateway   IPv6Subnet  IPv6Gateway  Cfgd Tag
------  -------     -------  ----------  ----------  -------      ------    ----------  -----------  ---------
blue    contiv-net  data     vxlan       0           10.1.2.0/24  10.1.2.1
```

然后如3.4.1所示，创建nginx, 指定blue作为tenant，会发现blue内的pod和default内的pod互相不同，实现了不同租户的隔离。

### 3.5 不同可用区 – bridge vxlan方式
instance-1 instance-2 是在相同可用区，新扩容一个instance-3，instance-3和instance-1，instance-2是在不同的可用区。(搭建的时候发现一个问题：创建的netmaster 默认是schedule到instance-3上，导致启动不了，后来通过给netmaster设置nodeSelector将netmaster 调度到instance-1上解决)。


```
[root@instance-ra68ebjl-1 ~]# netctl global set --fwd-mode bridge
[root@instance-ra68ebjl-1 ~]# netctl net create -t default --subnet=20.1.1.0/24 -g 20.1.1.1 default-net
[root@instance-ra68ebjl-1 ~]# netctl net ls -a
Tenant   Network      Nw Type  Encap type  Packet tag  Subnet       Gateway   IPv6Subnet  IPv6Gateway  Cfgd Tag
------   -------      -------  ----------  ----------  -------      ------    ----------  -----------  ---------
default  default-net  data     vxlan       0           20.1.1.0/24  20.1.1.1
[root@instance-ra68ebjl-1 backup]# kubectl get pods -o wide --all-namespaces
NAMESPACE     NAME                                   READY     STATUS    RESTARTS   AGE       IP             NODE           NOMINATED NODE
default       nginx-649846d457-bvb26                 1/1       Running   0          29s       20.1.1.4       192.168.0.24   <none>
default       nginx-649846d457-f7mqq                 1/1       Running   0          29s       20.1.1.2       192.168.1.6    <none>
default       nginx-649846d457-t8clh                 1/1       Running   0          29s       20.1.1.3       192.168.0.25   <none>
```

测试网络连同性：跨不同可用区，也是只有一跳即可到达。


```
[root@instance-ra68ebjl-1 backup]# kubectl exec -it nginx-649846d457-bvb26 /bin/sh
/ # traceroute 20.1.1.2 -n
 to 20.1.1.2 (20.1.1.2), 30 hops max, 46 byte packets
 1  20.1.1.2  1.625 ms  1.493 ms  1.378 ms
```

### 3.6 不同可用区 – bridge vlan方式
这种方式不支持跨不同可用区。pod之间相互不通。

参考：https://contiv.io/documents/networking/l2-vlan.html

需要配置vlan interface在switch上。需要依赖外面的switch。

### 3.7 不同可用区 – routing 方式
设置routing模式

[root@instance-ra68ebjl-1 ~]# netctl global set --fwd-mode routing
路由方式的BGP 配置Step: https://contiv.io/documents/networking/bgp.html, 配置比较麻烦。

需要依赖外面的switch配置BGP。

## 4. 总结
通过调研，发现可以在CCE上部署Contiv, 并且可以用vxlan overlay的方式。对于vlan和BGP，需要依赖外部的switch，并没有撘出来，contiv比较强大的功能还是Tenant和网络限速。

## 5. 参考
https://contiv.io/documents/networking/concepts.html
https://contiv.io/documents/tutorials/networking-kubernetes-16.html
