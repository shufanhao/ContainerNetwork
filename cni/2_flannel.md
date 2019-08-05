## 1. 什么是Flannel
Flannel是CoreOS团队设计并开源的一个容器网络解决方案。简单来说，它的功能是让集群中的不同节点主机创建的Docker容器都具有全集群唯一的IP地址。

Flannel 可以使用不同的 backend 来实现跨节点访问，比如 vxlan overlay 的方式.

Flannel github:  https://github.com/coreos/flannel 

## 2. 如何在现有CCE集群中搭建Flannel
### 2.1 前提条件
已经搭建好CCE集群。如下是我的work节点环境, cluster id: c-FjuTLDE7


instance-1：192.168.0.5	

instance-2: 192.168.0.4

### 2.2 修改CCE默认配置
因为CCE上的k8s集群是用云服务商提供的在VPC上配置路由的方法，实现POD间跨节点通信的，所以如果用flannel，需要将这种方式换掉。

在master节点，停止kube-cloud-controller


```
service kube-cloud-controller stop
```

修改work节点的kubelet启动参数。将原来的cloud-provide，cloud-config 参数去掉，network-plugin=kubenet 修改为cni。修改之后，示例如下。并且记录下容器网络ip, 可以从下面参数中取到：non-masquerade-cidr。其他关于CNI的配置参数，用默认值即可。

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
work节点上，shutdown cbr0。因为不会用kubenet, 而是用cni提供容器网络。


```
$ ifconfig cbr0 down
```
### 2.3 创建Flannel
修改如下yaml中的net-conf.json 的network参数为你的容器网络IP。我的是： 172.16.0.0/16。

在任意一节点上执行： kubectl apply -f flannel.yaml， flannel.yaml如下。

看yaml可以知道，该pod有两个container:

install-cni: 将config-map中适用于该flannel的CNI配置文件copy到主机的CNI 配置路径下, 这个路径和kubelet默认的cni配置文件路径一致。
kube-flannel：启动flanneld

```
---
apiVersion: extensions/v1beta1
kind: PodSecurityPolicy
metadata:
  name: psp.flannel.unprivileged
  annotations:
    seccomp.security.alpha.kubernetes.io/allowedProfileNames: docker/default
    seccomp.security.alpha.kubernetes.io/defaultProfileName: docker/default
    apparmor.security.beta.kubernetes.io/allowedProfileNames: runtime/default
    apparmor.security.beta.kubernetes.io/defaultProfileName: runtime/default
spec:
  privileged: false
  volumes:
    - configMap
    - secret
    - emptyDir
    - hostPath
  allowedHostPaths:
    - pathPrefix: "/etc/cni/net.d"
    - pathPrefix: "/etc/kube-flannel"
    - pathPrefix: "/run/flannel"
  readOnlyRootFilesystem: false
  # Users and groups
  runAsUser:
    rule: RunAsAny
  supplementalGroups:
    rule: RunAsAny
  fsGroup:
    rule: RunAsAny
  # Privilege Escalation
  allowPrivilegeEscalation: false
  defaultAllowPrivilegeEscalation: false
  # Capabilities
  allowedCapabilities: ['NET_ADMIN']
  defaultAddCapabilities: []
  requiredDropCapabilities: []
  # Host namespaces
  hostPID: false
  hostIPC: false
  hostNetwork: true
  hostPorts:
  - min: 0
    max: 65535
  # SELinux
  seLinux:
    # SELinux is unsed in CaaSP
    rule: 'RunAsAny'
---
kind: ClusterRole
apiVersion: rbac.authorization.k8s.io/v1beta1
metadata:
  name: flannel
rules:
  - apiGroups: ['extensions']
    resources: ['podsecuritypolicies']
    verbs: ['use']
    resourceNames: ['psp.flannel.unprivileged']
  - apiGroups:
      - ""
    resources:
      - pods
    verbs:
      - get
  - apiGroups:
      - ""
    resources:
      - nodes
    verbs:
      - list
      - watch
  - apiGroups:
      - ""
    resources:
      - nodes/status
    verbs:
      - patch
---
kind: ClusterRoleBinding
apiVersion: rbac.authorization.k8s.io/v1beta1
metadata:
  name: flannel
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: flannel
subjects:
- kind: ServiceAccount
  name: flannel
  namespace: kube-system
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: flannel
  namespace: kube-system
---
kind: ConfigMap
apiVersion: v1
metadata:
  name: kube-flannel-cfg
  namespace: kube-system
  labels:
    tier: node
    app: flannel
data:
  cni-conf.json: |
    {
      "name": "cbr0",
      "plugins": [
        {
          "type": "flannel",
          "delegate": {
            "hairpinMode": true,
            "isDefaultGateway": true
          }
        },
        {
          "type": "portmap",
          "capabilities": {
            "portMappings": true
          }
        }
      ]
    }
  net-conf.json: |
    {
      "Network": "172.16.0.0/16",
      "Backend": {
        "Type": "vxlan"
      }
    }
---
apiVersion: extensions/v1beta1
kind: DaemonSet
metadata:
  name: kube-flannel-ds
  namespace: kube-system
  labels:
    tier: node
    app: flannel
spec:
  template:
    metadata:
      labels:
        tier: node
        app: flannel
    spec:
      hostNetwork: true
      tolerations:
      - operator: Exists
        effect: NoSchedule
      serviceAccountName: flannel
      initContainers:
      - name: install-cni
        image: quay.io/coreos/flannel:v0.11.0-amd64
        command:
        - cp
        args:
        - -f
        - /etc/kube-flannel/cni-conf.json
        - /etc/cni/net.d/10-flannel.conflist
        volumeMounts:
        - name: cni
          mountPath: /etc/cni/net.d
        - name: flannel-cfg
          mountPath: /etc/kube-flannel/
      containers:
      - name: kube-flannel
        image: quay.io/coreos/flannel:v0.11.0-amd64
        command:
        - /opt/bin/flanneld
        args:
        - --ip-masq
        - --kube-subnet-mgr
        resources:
          requests:
            cpu: "100m"
            memory: "50Mi"
          limits:
            cpu: "100m"
            memory: "50Mi"
        securityContext:
          privileged: false
          capabilities:
             add: ["NET_ADMIN"]
        env:
        - name: POD_NAME
          valueFrom:
            fieldRef:
              fieldPath: metadata.name
        - name: POD_NAMESPACE
          valueFrom:
            fieldRef:
              fieldPath: metadata.namespace
        volumeMounts:
        - name: run
          mountPath: /run/flannel
        - name: flannel-cfg
          mountPath: /etc/kube-flannel/
      volumes:
        - name: run
          hostPath:
            path: /run/flannel
        - name: cni
          hostPath:
            path: /etc/cni/net.d
        - name: flannel-cfg
          configMap:
            name: kube-flannel-cfg
```

检查flannel是否启动成功, 


```
[root@instance-ly66xjyo-1 ~]# kubectl get pods -o wide --all-namespaces | grep flannel
kube-system   kube-flannel-ds-r7pfx                  1/1       Running            0          1h        192.168.0.4   192.168.0.4   <none>
kube-system   kube-flannel-ds-xh762                  1/1       Running            0          1h        192.168.0.5   192.168.0.5   <none>
至此，已经完成CCE上搭建Flannel的过程。
```


## 3. Flannel 网络分析
### 3.1 VXLAN 模式分析
VXLAN是Linux内核本身支持的一种网络虚拟化技术，是内核的一个模块，在内核态实现封装解封装，构建出overlay网络，其实就是一个由各宿主机上的Flannel.1设备组成的虚拟二层网络。

一旦flanneld启动，它将从etcd中读取配置，并请求获取一个subnet lease(租约),  有效期目前是24hrs，并且监视etcd的数据更新。flanneld一旦获取subnet租约、配置完backend，它会将一些信息写入/run/flannel/subnet.env文件。


```
[root@instance-uf0hnfr5-1 ~]# cat /run/flannel/subnet.env
FLANNEL_NETWORK=172.16.0.0/16
FLANNEL_SUBNET=172.16.0.1/24
FLANNEL_MTU=1450
FLANNEL_IPMASQ=true
在flannel：172.16.0.0/16这个大网下，每个kubernetes node从中分配一个子网片段(/24)，分别是：172.16.1.0/24, 172.16.0.0/24。
```


部署nginx,  kubectl apply -f nginx.yaml, yaml 如下


```
apiVersion: extensions/v1beta1
kind: Deployment
metadata:
  name: nginx-deployment
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
    spec:
      containers:
      - name: nginx
        image: hub.baidubce.com/cce/nginx-alpine-go:latest
```

在worker节点上发现多出来2个网络接口，cni0 和 flannel.1 如下。


```
cni0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1450
        inet 172.16.0.1  netmask 255.255.255.0  broadcast 0.0.0.0
        inet6 fe80::5c37:86ff:fe4a:520c  prefixlen 64  scopeid 0x20<link>
        ether 0a:58:ac:10:00:01  txqueuelen 1000  (Ethernet)
        RX packets 14  bytes 556 (556.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 2086  bytes 100620 (98.2 KiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
flannel.1: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1450
        inet 172.16.0.0  netmask 255.255.255.255  broadcast 0.0.0.0
        inet6 fe80::ac90:edff:fe29:2f65  prefixlen 64  scopeid 0x20<link>
        ether ae:90:ed:29:2f:65  txqueuelen 0  (Ethernet)
        RX packets 1  bytes 84 (84.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 1  bytes 84 (84.0 B)
        TX errors 0  dropped 8 overruns 0  carrier 0  collisions 0
```

可以看出：

我们用的默认的模式，vxlan，overlay network
flanneld创建一个flannel.1接口，专门用来封装隧道协议的，vxlan里面称为vtep
flanneld为每个Pod创建一对veth虚拟设备，一端放在容器接口上，另一端放在cni0 bridage上。可以通过brctl show cni0 查看和它绑定的接口。
Pod IP 分布：


```
[root@instance-uf0hnfr5-1 ~]# kubectl get pods -o wide
NAME                                READY     STATUS    RESTARTS   AGE       IP           NODE          NOMINATED NODE
nginx-deployment-59ffb955b4-h5csb   1/1       Running   0          2h        172.16.1.2   192.168.0.4   <none>
nginx-deployment-59ffb955b4-j85hp   1/1       Running   0          2h        172.16.1.3   192.168.0.4   <none>
nginx-deployment-59ffb955b4-l62s7   1/1       Running   0          2h        172.16.0.5   192.168.0.5   <none>
```

网络图如下：
![image](https://github.com/shufanhao/ContainerNetwork/blob/master/image/cni/flannel-packet.png)

Packet从pod出发。Pod1 ping Pod3

```
pod1的路由如下：

/ # ip route
default via 172.16.1.1 dev eth0
172.16.0.0/16 via 172.16.1.1 dev eth0
172.16.1.0/24 dev eth0 scope link src 172.16.1.2

在pod1中，发现pod3不在直连网络中，而是从default路由，default路由是172.16.1.1,也就是cni0的地址。



cni0 与 flannel.1 之间的packet转发
packet到达cni0之后，发现目的地址是172.16.0.5 要接着寻找下一跳地址。根据路由表信息，发现下一跳地址是flannel.1

[root@instance-uf0hnfr5-1 ~]# ip route
default via 192.168.0.1 dev eth0  proto dhcp  metric 100
172.16.0.0/24 via 172.16.0.0 dev flannel.1 onlink
192.168.0.0/16 dev eth0  proto kernel  scope link  src 192.168.0.4  metric 100
```
flannel.1 作用：
flannel.1也就是常说的vtep，进行vxlan的封包和解包。packet到达flannel.1之后发现目的地址不是自己，也要尝试将packet发送出去。数据包沿着网络协议栈向下流动时，填写目的mac地址时，要发出arp 广播："who is 172.16.0.5", vxlan设备的特殊性在于没有发送该广播地址。有个内核参数设置：


```
$ cat /proc/sys/net/ipv4/neigh/flannel.1/app_solicit
0
```

而是linux kernel引发一个”L3 MISS”事件并将arp请求发到用户空间的flanned程序。flanneld收到后并不会向外网发送arp request，而是尝试从etcd查找该地址匹配的子网的vtep信息。etcd存储了每个node节点和分配的pod 网络的映射关系以及对应的vtep的mac地址。这样就找到了对端的vtep的mac地址。目前为止的packet是：

Ethernet header: from node 2 flannel.1 mac to node 1的flannel.1的mac；  IP header: from pod1 ip to pod3 ip。这个packet还不能在物理网络上传输，因为实际上还是vxaln tunnel得packet。

kernel的vxlan封包
flannel.1为vxlan设备，linux kernel可以自动识别，并将上面的packet进行vxlan封包处理。在这个封包过程中，kernel需要知道该数据包究竟发到哪个node上去。kernel需要查看node上的fdb(forwarding database)以获得上面对端vtep设备（已经从arp table中查到其mac地址：node 1的flannel.1的mac）所在的node地址。如果fdb中没有这个信息，那么kernel会向用户空间的flanned程序发起”L2 MISS”事件。flanneld收到该事件后，会查询etcd，获取该vtep设备对应的node的”Public IP“，并将信息注册到fdb中。目标ip是node1，查找路由表包应该从eth0发出。
Node1 vxlan拆包
node1上的eth0接收到上述vxlan包，kernel将识别出这是一个vxlan包，于是拆包后将flannel.1 packet转给vtep（flannel.1). node1上的flannel.1再将这个数据包转到cni0，继而由docker0传输到Pod3的容器里。
### 3.2 host-gw/directrouting 模式分析
由于VXLAN由于额外的封包解包，导致其性能较差，所以Flannel就有了host-gw模式，即把宿主机当作网关，除了本地路由之外没有额外开销，性能和calico差不多，由于没有叠加来实现报文转发，这样会导致路由表庞大。因为一个节点对应一个网络，也就对应一条路由条目。但是这种模式要求：

是各个物理节点必须在同一个二层网络中，直接通过路由转发数据包。CCE中，同一个VPC内的node节点，如果在同一个可用区是可以用这样的方式，因为同一个可用区是在同一个二层网络中。不同可用区是在不同的子网中。

directrouting和host-gw区别是： directrouting根据网络情况，如果在同一个网段中用host-gw的方式，如果不在就用vxlan的方式。

试着改成host-gw模式（先删除现有的flannel damonset，然后修改configmap再部署）后在node2上路由表如下，多了 172.16.0.0/24 via 192.168.0.5 dev eth0。

```
[root@instance-uf0hnfr5-2 ~]# ip route
default via 192.168.0.1 dev eth0 proto dhcp metric 100
169.254.169.254 via 192.168.0.3 dev eth0 proto dhcp metric 100
172.16.0.0/24 via 192.168.0.5 dev eth0
172.16.1.0/24 dev cni0 proto kernel scope link src 172.16.1.1
172.17.0.0/16 dev docker0 proto kernel scope link src 172.17.0.1
192.168.0.0/16 dev eth0 proto kernel scope link src 192.168.0.4 metric 100
```
## 4. 参考

https://tonybai.com/2017/01/17/understanding-flannel-network-for-kubernetes/ 

http://www.8tool.club/tool/aricl/3/60878.html


