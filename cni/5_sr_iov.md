# CCE SRIOV 调研


[toc]

## SRIOV 是什么
SR-IOV 标准允许在虚拟机之间高效共享 PCIe（Peripheral Component Interconnect Express，快速外设组件互连）设备，并且它是在硬件中实现的，可以获得能够与本机性能媲美的 I/O 性能。SR-IOV 规范定义了新的标准，根据该标准，创建的新设备可允许将虚拟机直接连接到 I/O 设备（SR-IOV 规范由 PCI-SIG 在 http://www.pcisig.com 上进行定义和维护）。单个 I/O 资源可由许多虚拟机共享。共享的设备将提供专用的资源，并且还使用共享的通用资源。这样，每个虚拟机都可访问唯一的资源。因此，启用了 SR-IOV 并且具有适当的硬件和 OS 支持的 PCIe 设备（例如以太网端口）可以显示为多个单独的物理设备，每个都具有自己的 PCIe 配置空间。
SR-IOV（Single Root I/O Virtualization）是一个将PCIe共享给虚拟机的标准，通过为虚拟机提供独立的内存空间、中断、DMA流，来绕过VMM实现数据访问。SR-IOV基于两种PCIe functions：

- PF (Physical Function)： 包含完整的PCIe功能，包括SR-IOV的扩张能力，该功能用于SR-IOV的配置和管理。
- VF (Virtual Function)： 包含轻量级的PCIe功能。每一个VF有它自己独享的PCI配置区域，并且可能与其他VF共享着同一个物理资源


## 如何配置
### BIOS 中开启 SRIOV 支持
BROADCOM 网卡参考这篇文档 http://kms2.h3c.com/View.aspx?id=59149

### iommu
iommu 是否需要开启待确认，可能会有性能损失

### 驱动
加载驱动，驱动 options 可以配置最大 VF 数量。之后可以通过 ` lspci -nn | grep Ethernet ` 看到 VF 了。
```shell
modprobe ixgbe max_vf=32
```

### 永久开启
上述方法只是临时配置 VF，如需永久开启，需要在 grub 配置文件中添加如下内容，重启机器
示例如下：
```shell
intel_iommu=on ixgbe.max_vfs=32
```

### 当前环境
iommu 未开启，待确认是否必须


## 测试
### 物理网卡（PF）
物理网卡作为 VF 的 master 设备，VF 是基于物理网卡的支持才可以创建出来的。

通过如下命令查看 PCI 网络设备

物理网卡（PF）为第一行，PCI ID 为 1a:00:0
通过 PCI ID 查看网卡



### 虚拟网卡（VF）
查看 PF 支持的 VF 数量以及创建出来的 VF 数量


totalvfs 为 PF 支持的总的 vf 数量，numvfs 为已经创建出来的 vf 数量。
可以看到已经分配了 1 个 vf，上面的 ` lspci -nn | grep Ethernet ` 命令的返回结果可以看到创建的 VF 网卡

每创建一个 VF，就会在 ` /sys/class/net/<PF-name>/device/ ` 中创建一个目录 virtfn** 记录该 VF 网卡


同时，host network namespace 中也可以通过 ` ip link ` 看到该网卡

#### 如何支持容器呢？
和 macvlan、eni、calico 等方式一样

```shell
// 创建容器 network namespace
ip netns add <container-ns>
// 将 VF 放入容器 network namespace 中
ip link set <VF name> netns <container-ns>
// 将 VF 网卡 UP
ip netns exec <container-ns> ip link set <VF name> up
// 为 VF 配置 IP、route
ip netns exec <container-ns> ip a add 192.168.0.4/24 dev <VF name>
ip netns exec <container-ns> ip r add default via 192.168.0.1 dev <VF name>
```
#### 如何支持容器内访问 clusterIP？
##### 为什么无法访问 clusterIP?
clusterIP 为一个虚拟 IP，当访问 clusterIP 时，转发到真实的 podIP:port
（1）容器内无 iptables 规则或者 ipvs 规则，无法找到 podIP:port
（2）sriov 的 VF 网卡为物理网卡 PF 虚拟出来的网卡，数据包从容器中出来直接到了物理网卡，未经过 host network namespace 协议栈，因此也无法找到 podIP:port

##### 如何解决？

（1）容器使用两张网卡，添加一个  veth pair，到 clusterIP 网段的数据包，从 veth 到 host network namespace，走一遍 iptables 规则

下面是瞎想的方法：
（2）ClusterIP 使用真实的可路由的 IP，配置 nginx 使用该 IP，nginx 反代到 pod
（3）容器内起一个 kube-proxy 。。。

## 客户如何使用？
### 硬件环境和主机配置

- 支持 sriov 的网卡
- bios 开启 sriov 支持
- 操作系统 grub 配置开启 iommu
- 启动时加载网卡驱动，并创建好 sriov 网卡

### CNI

使用 华为 CNI-GENIE
calico + sriov 方案

#### 编译 sriov CNI
下载 https://github.com/hustcat/sriov-cni 代码，并上传到开发机上
进入代码目录，执行 ` ./build ` 命令编译 sriov CNI，二进制文件在 bin 目录中

#### kubernetes worker 节点配置

- 将 sriov 二进制文件上传到 worker 节点 /opt/cni/bin 目录中
- /etc/cni/net.d/ 目录添加 sriov 配置文.

#### pod yaml
```yaml
apiVersion: extensions/v1beta1
kind: Deployment
metadata:
  name: deployment-example
  labels:
    app: nginx
spec:
  replicas: 1
  minReadySeconds: 0
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 25%
      maxUnavailable: 25%
  selector:
    matchLabels:
      app: nginx
  template:
    metadata:
      annotations:
        cni: "calico, sriov"
      labels:
        app: nginx
    spec:
      restartPolicy: Always
      containers:
        - name: nginx
          image: hub.baidubce.com/cce/nginx-alpine-go:latest
      nodeSelector:
        kubernetes.io/hostname: test
```

#### pod 网络情况

eth0 为 calico 网卡，eth1 为 sriov 网卡
路由表中 10.96.0.0/12 为 clusterIP 网段，通过 calico 的 veth 网卡出去

## 参考文档

* https://software.intel.com/en-us/articles/single-root-inputoutput-virtualization-sr-iov-with-linux-containers
* https://blog.scottlowe.org/2009/12/02/what-is-sr-iov/
* http://kms2.h3c.com/View.aspx?id=59149
* https://sdn.feisky.xyz/wang-luo-ji-chu/index-1/sr-iov
