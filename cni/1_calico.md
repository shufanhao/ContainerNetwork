## 1 What is Calico
Calico可以创建并管理一个3层平面网络，为每个工作负载分配一个完全可路由的IP地址。 工作负载可以在没有IP封装或网络地址转换的情况下进行通信，以实现裸机性能，简化故障排除和提供更好的互操作性。 在需要使用overlay网络的环境中，Calico提供了IP-in-IP隧道技术。
Calico在每一个计算节点利用Linux Kernel实现了一个高效的vRouter来负责数据转发，而每个vRouter通过BGP协议负责把自己上运行的workload的路由信息像整个Calico网络内传播——小规模部署可以直接互联，大规模下可通过指定的BGP route reflector来完成。
Calico节点组网可以直接利用数据中心的网络结构（无论是L2或者L3），不需要额外的NAT，隧道或者Overlay Network。
Calico基于iptables还提供了丰富而灵活的网络Policy，保证通过各个节点上的ACLs来提供Workload的多租户隔离、安全组以及其他可达性限制等功能。这一点flannel做不到。
Calico: https://www.projectcalico.org/ 

## 2 How it work 
### 2.1 Calico IPIP与BGP模式
IPIP是一种将各Node的路由之间做一个tunnel，再把两个网络连接起来的模式。启用IPIP模式时，Calico将在各Node上创建一个名为”tunl0″的虚拟网络接口。如果集群节点不在同一子网内，需要通过集群外部的三层设备作为网关通信，这时因为三层设备没有pod网段的路由，需要配置calico成IPIP模式，通过tunnel穿越。其实还是通过BGP协议来传递路由的，带来的问题是：性能上的损耗。

BGP模式则直接使用物理机作为虚拟路由路（vRouter）， 不再创建额外的tunnel。如果集群节点全在同一子网内，可以使用BGP传递路由

图：IPIP模式
![image](https://github.com/shufanhao/ContainerNetwork/blob/master/image/cni/calico-ipip-arch.png)

## 2.2 Calico 主要组件
Calico BGP模式在小规模集群中可以直接互联，BGP peer之间是一个全mesh的结构。在大规模集群中可以通过额外的BGP route reflector来完成。架构图如下：
![image](https://github.com/shufanhao/ContainerNetwork/blob/master/image/cni/calico-arch.png)

1. Felix。是一个守护程序。 Felix 负责编制路由和ACL规则以及在该主机上所需的任何其他内容，以便为该主机上的endpoints资源正常运行提供所需的网络连接。
2. ETCD。Calico使用etcd提供组件之间的数据通信，并作为可以保证一致性的数据存储，以确保Calico始终可以构建出一个准确的网络。另外calico也提供(Installing with the Kubernetes API datastore)，也就是用k8s api 作为datastore。
3. BGP Client(BIRD)。读取Felix程序编写到内核中并在数据中心内分发的路由信息，并且将这些路由信息宣告出去。
4. BGP Route Reflector (BIRD)。对于较大规模的部署，简单的BGP可能成为限制因素，因为全mesh的这种结构，会让客户端性能越来越差。而采用route reflector这个是BGP协议自带的功能。当Calico BGP客户端将路由从其FIB通告到Route Reflector时，Route Reflector会将这些路由通告给部署集群中的其他节点。
5. BIRD 是个开源的使用 BGP(http://bird.network.cz/) 分发 route 的 daemon。
## 2.3 BGP协议
BGP 协议的发明可以说让整个互联网得以快速发展。BGP有如下特性：
1. BGP支持数十万条路由更新信息;
2. 安全性高，支持更为丰富的路由过滤工具; 
3. IGP 仅仅考虑是不是最佳路由，而BGP是对路由高可用性，需要对进入或者离开AS的流量进行选路录策略控制。BGP协议是连同不同AS号的网络。不同AS号可以理解成连同骨干网上不同运营商之间的网络。 AS是处于同一技术掌控以及政策掌控之下的连续路由域。所有的公网路由，都是由BGP承载。IGP负责域内，BGP负责域间。AS号是一个32bit的数字， 每个自治网络都需要申请自己的AS编号，联通的AS号是9800。

典型的结构图如下：R1属于AS1, R2/R3是AS2，R1和R2跑EBGP, R2和R3跑IBGP，最终通过配置可以实现r1上ping通R3: 3.3.3.3。
![image](https://github.com/shufanhao/ContainerNetwork/blob/master/image/cni/bgp-demo.png)


配置如下：

```
R1:

interface Loopback0
 ip address 1.1.1.1 255.255.255.255
!
interface FastEthernet1/0
 ip address 192.168.1.1 255.255.255.0
 duplex half
!
router bgp 1
 no synchronization
 bgp log-neighbor-changes
 network 1.1.1.1 mask 255.255.255.255
 neighbor 192.168.1.2 remote-as 2
 no auto-summary
!
R2， 需要在一个AS内跑一个igp，来保证bgp neighbor之间是可以ping通的，注意如果neighbor是Loopback一定要加update-source,防止BGP作校验

interface Loopback0
 ip address 2.2.2.2 255.255.255.255
!
interface FastEthernet1/0
 ip address 192.168.1.2 255.255.255.0
 duplex auto
 speed auto
!
interface FastEthernet1/1
 ip address 192.168.2.1 255.255.255.0
 duplex auto
 speed auto
!
router eigrp 1
 network 2.0.0.0
 network 192.168.2.0
 no auto-summary
!
router bgp 2
 no synchronization
 bgp log-neighbor-changes
 neighbor 3.3.3.3 remote-as 2
 neighbor 3.3.3.3 update-source Loopback0
 neighbor 3.3.3.3 next-hop-self
 neighbor 192.168.1.1 remote-as 1
 no auto-summary
R3:

interface Loopback0
 ip address 3.3.3.3 255.255.255.255
!
interface FastEthernet1/0
 ip address 192.168.2.2 255.255.255.0
 duplex half
!
router eigrp 1
 network 3.0.0.0
 network 192.168.2.0
 no auto-summary
!
router bgp 2
 bgp log-neighbor-changes
 neighbor 2.2.2.2 remote-as 2
 neighbor 2.2.2.2 update-source Loopback0
 !
 address-family ipv4
  redistribute connected
  neighbor 2.2.2.2 activate
  no auto-summary
  no synchronization
 exit-address-family
!
最终R3上可以学习到R1的路由：

R3#show ip route
Codes: C - connected, S - static, R - RIP, M - mobile, B - BGP
       D - EIGRP, EX - EIGRP external, O - OSPF, IA - OSPF inter area
       N1 - OSPF NSSA external type 1, N2 - OSPF NSSA external type 2
       E1 - OSPF external type 1, E2 - OSPF external type 2
       i - IS-IS, su - IS-IS summary, L1 - IS-IS level-1, L2 - IS-IS level-2
       ia - IS-IS inter area, * - candidate default, U - per-user static route
       o - ODR, P - periodic downloaded static route

Gateway of last resort is not set

     1.0.0.0/32 is subnetted, 1 subnets
B       1.1.1.1 [200/0] via 2.2.2.2, 00:17:45
     2.0.0.0/32 is subnetted, 1 subnets
D       2.2.2.2 [90/156160] via 192.168.2.1, 00:21:08, FastEthernet1/0
     3.0.0.0/32 is subnetted, 1 subnets
C       3.3.3.3 is directly connected, Loopback0
C    192.168.2.0/24 is directly connected, FastEthernet1/0

```
## 3 CCE 集群搭建 Calico
### 3.1 前提条件
已经搭建好CCE集群。如下是我的work节点环境, cluster id: c-VPWCtv0J 。其中注意instance-2和instance-3是在一个相同可用区，而instance-1是在不同可用区，也就是在不同的一个子网。所以如果用BGP的话，instance-1 和 instance 2/3是不能打通的。


- instance-1: 192.168.1.4	
- instance-2: 192.168.0.4
- instance-3: 192.168.0.5
### 3.2 修改CCE默认配置
因为CCE上的k8s集群是用云服务商提供的在VPC上配置路由的方法，实现POD间跨节点通信的，所以如果用Calico，需要将这种方式换掉。

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

### 3.3 创建Calico
因为worker节点上不能访问到master ETCD，也懒得去搭建另外的ETCD，所以没用 "Installing with the etcd datastore" 而是用"Installing with the Kubernetes API datastore", 也就是用k8s api 作为datastore。

修改calico.yaml中的net-conf.json 的network参数为你的容器网络IP。我的是： 172.16.0.0/16。

在任意一节点上执行：
```
kubectl apply -f flannel.yaml
```
yaml中ConfigMap部分主要是：

- cni_network_config：符合CNI规范的网络配置，其中type=calico表示，Kubelet从 CNI_PATH(默认为/opt/cni/bin)找名为calico的可执行文件，用于容器IP地址的分配。

yaml可以知道，该pod有两个container:

- install-cni: 各Node上安装CNI二进制文件到/opt/cni/bin目录下，并安装相应的网络配置文件到/etc/cni/net.d目录下。
- calico-node：calico服务程序，用于设置Pod的网络资源，保证pod的网络与各Node互联互通，它还需要以HostNetwork模式运行，直接使用宿主机网络
。 注意： CALICO_IPV4POOL_IPIP="always"，使用IPIP模式时。设置为"off"，此时将使用BGP模式。默认是用IPIP模式。
```
[root@instance-tey6kh1n ~]# kubectl get pods -o wide --all-namespaces | grep calico
kube-system   calico-node-222tf                      1/1       Running   0          2h        192.168.1.4   192.168.1.4   <none>
kube-system   calico-node-4h2tz                      1/1       Running   0          2h        192.168.0.4   192.168.0.4   <none>
kube-system   calico-node-7x8dw                      1/1       Running   0          1h        <none>        192.168.0.5   <none>
至此，已经完成CCE上搭建Calico的过程。
```
关于IPAM的配置有两种：

host-local 传入的subnet是usePodCidr，calico会读取该节点的podCidr，可以通过"kubectl get node xxxx -o yaml " 知道。分配的ip都放在本地一个目录里。podCIDR是controller-management创建node资源的时候，由CM分配的。


```
# cd /var/lib/cni/networks/k8s-pod-network
# ls
10.244.0.2  10.244.0.3  10.244.0.4  10.244.0.5  10.244.1.2  10.244.1.3  10.244.1.4  10.244.4.2  last_reserved_ip.0  lock
```
calico-ipam: 

默认情况下，当网络中出现第一个容器，calico会为容器分配一段子网(子网掩码/26，例如：172.0.118.0/26)，后续出现该节点上的pod都从这个子网中分配ip地址，这样做的好处是能够缩减节点上的路由表的规模，按照这种方式节点上2^6=64个ip地址只需要一个路由表项就行了，而不是为每个ip单独创建一个路由表项。如下为etcd中看到的子网段的值。注意：当64个主机位都用完之后，会从其他可用的的子网段中取值，所以并不是强制该节点只能运行64个pod ,只是增加了路由表项。


```
[root@edge-cloud
etcd]# ETCDCTL_API=3 etcdctl --endpoints=http://192.168.1.76:30772 get
"" --from-key
/calico/ipam/v2/assignment/ipv4/block/10.244.2.0-26
{"cidr":"10.244.2.0/26","affinity":null,"strictAffinity":false,"allocations":[0,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null],"unallocated":[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63],"attributes":[{"handle_id":null,"secondary":null}]}
/calico/ipam/v2/assignment/ipv4/block/10.244.2.64-26
```

注意：默认64是可以修改的，设置blocksize, 参考：https://www.projectcalico.org/calico-ipam-explained-and-enhanced/

本次搭建的CNI配置是如下第一个，datastore_type选用的是kubernetes。还可以用etcd如下第二个。


```
cni_network_config: |-
    {
      "name": "k8s-pod-network",
      "cniVersion": "0.3.0",
      "plugins": [
        {
          "type": "calico",
          "log_level": "info",
          "datastore_type": "kubernetes",
          "nodename": "__KUBERNETES_NODE_NAME__",
          "mtu": __CNI_MTU__,
          "ipam": {
            "type": "host-local",
            "subnet": "usePodCidr"
          },
          "policy": {
              "type": "k8s"
          },
          "kubernetes": {
              "kubeconfig": "__KUBECONFIG_FILEPATH__"
          }
        },
        {
          "type": "portmap",
          "snat": true,
          "capabilities": {"portMappings": true}
        }
      ]
    }
cni_network_config: |-
    {
      "name": "k8s-pod-network",
      "cniVersion": "0.3.0",
      "plugins": [
        {
          "type": "calico",
          "etcd_endpoints": "https://192.168.1.76:2379",
          "etcd_key_file": "/root/etcd/apiserver-etcd-client.key",
          "etcd_cert_file": "/root/etcd/apiserver-etcd-client.crt",
          "etcd_ca_cert_file": "/root/etcd/ca.crt",
          "log_level": "info",
          "ipam": {
              "type": "host-local",
              "subnet": "usePodCidr"
          },
          "kubernetes": {
              "kubeconfig": "/etc/cni/net.d/calico-kubeconfig"
          }
        },
        {
          "type": "portmap",
          "snat": true,
          "capabilities": {"portMappings": true}
        }
      ]
    }
```


### 3.4 安装和使用calicoctl
#### 3.4.1 calioctl 安装
calicoctl 是一个cli command，可以获取calico存储在etcd或者k8s api datastore的数据。按照步骤如下

```
curl -O -L  https://github.com/projectcalico/calicoctl/releases/download/v3.4.2/calicoctl
chmod +x calicoctl
cp calicoctl /usr/local/bin/
```
#### 3.4.2 calioctl 使用
refer: https://docs.projectcalico.org/v3.4/usage/calicoctl/configure/kdd 

用kubenetes作为Datastore


```
export DATASTORE_TYPE=kubernetes
export KUBECONFIG=~/.kube/config
calicoctl get workloadendpoints
如：calicoctl node status

[root@instance-tey6kh1n .kube]# calicoctl get workloadendpoints
WORKLOAD NODE NETWORKS INTERFACE
nginx-7fbd5f4c55-cvhmg 192.168.0.4 172.16.1.6/32 cali2b47ad3dda7
nginx-7fbd5f4c55-pkqbk 192.168.1.4 172.16.0.5/32 califf99b94eff9
nginx-7fbd5f4c55-qhwmv 192.168.0.5 172.16.2.4/32 calic6b612c8741
如果用etcd作为Datastore，要指定etcd endpoints和证书文件等，证书文件可以通过ps -ef | grep etcd 进行查看

export ETCD_ENDPOINTS=https://192.168.1.76:2379
export ETCD_KEY_FILE=/root/etcd/apiserver-etcd-client.key
export ETCD_CERT_FILE=/root/etcd/apiserver-etcd-client.crt
export ETCD_CA_CERT_FILE=/root/etcd/ca.crt
```


## 3. Calico 网络分析
### 3.1 IPIP 模式分析
172.16.0.0/16这个大网下，每个kubernetes node从中分配一个子网片段(/24)，分别是：172.16.1.0/24, 172.16.0.0/24,172.16.2.0/24。

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

在worker节点上发现多出来2个网络接口，calixxxx 和 tunl0 如下。

```
cali758de008042: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1440
        inet6 fe80::ecee:eeff:feee:eeee  prefixlen 64  scopeid 0x20<link>
        ether ee:ee:ee:ee:ee:ee  txqueuelen 0  (Ethernet)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
tunl0: flags=193<UP,RUNNING,NOARP>  mtu 1440
        inet 172.16.2.1  netmask 255.255.255.255
        tunnel   txqueuelen 1000  (IPIP Tunnel)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

可以看出：

calixxx，其实就是veth pair的一个，另一个接入container eth0
tunl0 实现IPIP隧道协议。

Pod IP 分布：


```
[root@instance-tey6kh1n ~]# kubectl get pods -o wide
NAME                                READY     STATUS    RESTARTS   AGE       IP           NODE          NOMINATED NODE
nginx-deployment-7fbd5f4c55-bnspl   1/1       Running   0          3h        172.16.2.2   192.168.0.5   <none>
nginx-deployment-7fbd5f4c55-h2rzk   1/1       Running   0          3h        172.16.0.3   192.168.1.4   <none>
nginx-deployment-7fbd5f4c55-s2w9w   1/1       Running   0          3h        172.16.1.4   192.168.0.4   <none>
Node calico 状态，可以看到在192.168.1.4节点上已经建立的ipv4 bgp peer 关系：

[root@instance-tey6kh1n .kube]#  calicoctl node status
Calico process is running.

IPv4 BGP status
+--------------+-------------------+-------+----------+-------------+
| PEER ADDRESS |     PEER TYPE     | STATE |  SINCE   |    INFO     |
+--------------+-------------------+-------+----------+-------------+
| 192.168.0.4  | node-to-node mesh | up    | 12:23:23 | Established |
| 192.168.0.5  | node-to-node mesh | up    | 12:23:10 | Established |
+--------------+-------------------+-------+----------+-------------+

IPv6 BGP status
No IPv6 peers found.
```
网络图如下：
![image](https://github.com/shufanhao/ContainerNetwork/blob/master/image/cni/calico-ipip-packet-path.png)


Packet从pod出发。Pod1(172.16.0.3) ping Pod2(172.16.1.4)
pod1的路由如下，注意：169.254.1.1是一个无效IP, 因为设置了一个静态ARP，mac地址就是host上caliifxxxx的mac。


```
/ # ip route
default via 169.254.1.1 dev eth0
169.254.1.1 dev eth0 scope link
/ # ip neig
169.254.1.1 dev eth0 lladdr ee:ee:ee:ee:ee:ee ref 1 used 0/0/0 probes 1 REACHABLE
```

Pod1上的host 路由分析
packet到达tunl0之后，发现目的地址是172.16.1.4 要接着寻找下一跳地址。根据路由表信息，发现下一跳是192.168.0.4, 然后根据默认路由会从eth0出去。


```
[root@instance-uf0hnfr5-1 ~]# ip route
default via 192.168.1.1 dev eth0  proto dhcp  metric 100
169.254.169.254 via 192.168.1.2 dev eth0  proto dhcp  metric 100
blackhole 172.16.0.0/24  proto bird
172.16.0.3 dev calif07d849539a  scope link
172.16.1.0/24 via 192.168.0.4 dev tunl0  proto bird onlink
172.16.2.0/24 via 192.168.0.5 dev tunl0  proto bird onlink
```
Pod2的host路由分析: 

匹配到172.16.1.4 dev cali319b21c6cb2  scope link， 然后经过tunl0到达容器内


```
[root@instance-txln5i0h ~]# ip route
default via 192.168.0.1 dev eth0  proto dhcp  metric 100
169.254.169.254 via 192.168.0.3 dev eth0  proto dhcp  metric 100
172.16.0.0/24 via 192.168.1.4 dev tunl0  proto bird onlink
blackhole 172.16.1.0/24  proto bird
172.16.1.4 dev cali319b21c6cb2  scope link
172.16.2.0/24 via 192.168.0.5 dev tunl0  proto bird onlink
```

从pod1 ping pod2， 并且在pod1的host上抓包如下，可以看到有inner ip 和 outer ip


```
[root@instance-tey6kh1n ~]# tcpdump -i eth0 host 192.168.0.4 -n
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on eth0, link-type EN10MB (Ethernet), capture size 65535 bytes
17:17:12.014861 IP 192.168.1.4 > 192.168.0.4: IP 172.16.0.3 > 172.16.1.4: ICMP echo request, id 13056, seq 116, length 64 (ipip-proto-4)
17:17:12.016320 IP 192.168.0.4 > 192.168.1.4: IP 172.16.1.4 > 172.16.0.3: ICMP echo reply, id 13056, seq 116, length 64 (ipip-proto-4)
```

### 3.2 BGP 模式分析
为什么要用BGP路由协议来传递路由呢？https://blog.51cto.com/weidawei/2152319 

将calico.yaml中的CALICO_IPV4POOL_IPIP的always改成off后，就是关掉ipip，启用bgp模式。并且执行命令： rmmod ipip，将tunl0删掉后，但是发现不work, 还是跑的bgp。然后自己创建另外一套cluster。

搭建好CCE集群。如下是我的work节点环境, cluster id: c-zHrQb2VO。



```
kubectl apply -f nginx.yaml, yaml 如下

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
    spec:
      containers:
      - name: nginx
        image: hub.baidubce.com/cce/nginx-alpine-go:latest
```

在worker节点上发现多出来1个网络接口，calixxxx, 并没有tunl0接口。


```
cali758de008042: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1440
        inet6 fe80::ecee:eeff:feee:eeee  prefixlen 64  scopeid 0x20<link>
        ether ee:ee:ee:ee:ee:ee  txqueuelen 0  (Ethernet)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```
Pod IP 分布：

```
[root@instance-jwoylcqf-2 ~]# kubectl get pods -o wide
NAME                     READY     STATUS    RESTARTS   AGE       IP           NODE          NOMINATED NODE
nginx-7fbd5f4c55-4dvps   1/1       Running   0          3s        172.18.0.4   192.168.0.7   <none>
nginx-7fbd5f4c55-rfmmq   1/1       Running   0          3s        172.18.1.6   192.168.0.6   <none>
```

网络图如下：
![image](https://github.com/shufanhao/ContainerNetwork/blob/master/image/cni/calico-bgp-packet-path.png)

Packet从pod出发。Pod1(172.18.1.6) ping Pod2(172.18.0.4)
pod1的路由如下，注意：169.254.1.1是一个无效IP, 因为设置了一个静态ARP，mac地址就是host上caliexxxx的mac。


```
/ # ip route
default via 169.254.1.1 dev eth0
169.254.1.1 dev eth0 scope link
/ # ip neig
169.254.1.1 dev eth0 lladdr ee:ee:ee:ee:ee:ee ref 1 used 0/0/0 probes 1 REACHABLE
```
Pod1上的host 路由分析
packet到达host上的caliexxx之后，发现目的地址是172.18.0.4 要接着寻找下一跳地址。linux的vRouter会找到下一条地址是192.168.0.7, 出口接口是eth0, 从eth0发送出去。


```
[root@instance-jwoylcqf-1 ~]# ip route
default via 192.168.0.1 dev eth0  proto dhcp  metric 100
172.18.0.0/24 via 192.168.0.7 dev eth0  proto bird
172.18.1.0/24 dev cbr0  proto kernel  scope link  src 172.18.1.1
172.18.1.6 dev calie432e518530  scope link
192.168.0.0/24 dev eth0  proto kernel  scope link  src 192.168.0.6  metric 100
```
Pod2的host路由分析

匹配到172.18.0.4 dev cali594714bf9fd scope link，通过vRouter直接转发进入容器。


```
[root@instance-jwoylcqf-2 ~]# ip route
default via 192.168.0.1 dev eth0  proto dhcp  metric 100
172.18.0.0/24 dev cbr0  proto kernel  scope link  src 172.18.0.1
172.18.0.4 dev cali594714bf9fd  scope link
172.18.1.0/24 via 192.168.0.6 dev eth0  proto bird
192.168.0.0/24 dev eth0  proto kernel  scope link  src 192.168.0.7  metric 100
```

## 4. Network-policy
Network Policy是一种kubernetes资源，经过定义、存储、配置等流程使其生效。

通过kubectl client创建network policy资源；calico的policy-controller监听network policy资源，获取到后写入calico的etcd数据库；node上calico-felix从etcd数据库中获取policy资源，调用iptables做相应配置。

参考：AWS用Calico做Stars策略演示， 实践过一遍确实可以。

## 5.Pod 固定IP
可以通过配置annotations来实现pod固定ip。
前提条件：

ipam不能用host-local, 只能是etcd
必须用etcd作为datastore, 而不是用kubernetes， 因为 Calico IPAM is not yet supported when using the kubernetes datastore.
必须用k8s作为policy:

无论部署的时候是用pod还是用deployment，可以通过加入annotation的方式，为pod固定IP: 

```
---
apiVersion: extensions/v1beta1
kind: Deployment
metadata:
  name: busybox01
  labels:
    app: busybox01
spec:
  replicas: 2
  selector:
    matchLabels:
      app: busybox01
  template:
    metadata:
      labels:
        app: busybox01
      annotations:
        "cni.projectcalico.org/ipAddrs": "[\"150.138.245.214\"]"
    spec:
      nodeName: test
      containers:
      - name: busybox01
        image: busybox:1.28
        command:
          - sleep
          - "3600"
        imagePullPolicy: IfNotPresent
```

## 6. 创建不同的IPPool
Calico支持为不同的Pod分配不同的IPPool，在创建Pod的时候加入annotation，或者对于不同的namespace用不同的annotation:

参考：https://www.tigera.io/blog/calico-ipam-explained-and-enhanced/ 

## 7. TC
Calico支持bandwidth 作为plugin支持TC。不管是calico-ipam还是hostlocal，都支持TC，经过测试都可行。

calico的conf配置如下：


```
[root@c-s8jfdzwk-uuotll2i ~]# cat /etc/cni/net.d/10-calico.conflist
{
  "name": "k8s-pod-network",
  "cniVersion": "0.3.0",
  "plugins": [
    {
      "type": "calico",
      "log_level": "info",
      "datastore_type": "kubernetes",
      "nodename": "192.168.3.137",
      "mtu": 1440,
      "ipam": {
          "type": "calico-ipam"
      },
     "policy": {
          "type": "k8s"
      },
      "kubernetes": {
          "kubeconfig": "/etc/cni/net.d/calico-kubeconfig"
      }
    },
    {
      "type": "portmap",
      "snat": true,
      "capabilities": {"portMappings": true}
    },
    {
      "type": "bandwidth",
      "capabilities": {"bandwidth": true}
    }
  ]
}
```

测试Pod yaml:


```
[root@c-s8jfdzwk-uuotll2i ~]# cat test1.yaml
apiVersion: v1
kind: Pod
metadata:
  name: test-1
  annotations:
    kubernetes.io/ingress-bandwidth: 10M
    kubernetes.io/egress-bandwidth: 10M
spec:
  containers:
  - name: samplepod-1
    imagePullPolicy: IfNotPresent
    image: mlabbe/iperf
```

发现其中一个节点上调度的Pod的TC是可以， 可以用iperf测试。

tc qdisc show 命令如下，红色框内部分是bandwidth plugin 生成的对应的命令。来控制入流量和出流量。
![image](https://github.com/shufanhao/ContainerNetwork/blob/master/image/cni/calico-tc.png)

## 8. Debug
可以通过ps -ef | grep calico 查看calico log放在哪里了.

felix 代码流程：https://www.lijiaocn.com/%E9%A1%B9%E7%9B%AE/2017/09/12/calico-felix.html

## 9. 总结
理论上分析，ipip模式因为会有packet封包和解包，性能上会比bgp差一点。但是ipip支持跨子网的网络互联。

## 10. 参考
https://docs.projectcalico.org/v3.5/getting-started/kubernetes/installation/calico
https://www.kubernetes.org.cn/4960.html
http://www.8tool.club/tool/aricl/3/60878.html
