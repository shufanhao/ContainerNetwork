## 1 CNI 介绍
CNI(Container Network Interface)，其基本思想为：Container Runtime在创建容器时，先创建好network namespace，然后调用CNI插件为这个netns配置网络，其后再启动容器内的进程。

CNI插件包括两部分：
- CNI Plugin负责给容器配置网络，它包括两个基本的接口
配置网络: AddNetwork(net *NetworkConfig, rt *RuntimeConf) (types.Result, error)
清理网络: DelNetwork(net *NetworkConfig, rt *RuntimeConf) error
- IPAM Plugin负责给容器分配IP地址，主要实现包括host-local和dhcp。
host-local: 基于本地文件的 ip 分配和管理，把分配的 IP 地址保存在文件中
dhcp:从已经运行的dhcp服务器中获取 ip 地址


Kubernetes Pod 中的其他容器都是Pod所属pause容器的网络，创建过程为：
1. kubelet 先创建pause容器生成network namespace
2. 调用网络CNI driver
3. CNI driver 根据配置调用具体的cni 插件
4. cni 插件给pause 容器配置网络
5. pod 中其他的容器都使用 pause 容器的网络


几个目录：
1. /opt/cni/bin: 存放cni 和 ipam的bin文件
2. /var/lib/cni/networks：对于host-local这种模式，存放已经分配的IP地址

## 2 怎么用CNI
看一下怎么使用CNI，会对理解CNI有个直观的认识。

1. 编译安装CNI的官方插件

$ mkdir -p $GOPATH/src/github.com/containernetworking/plugins
 
$ git clone https://github.com/containernetworking/plugins.git  $GOPATH/src/github.com/containernetworking/plugins
 
$ cd $GOPATH/src/github.com/containernetworking/plugins
 
$ ./build.sh
2. 创建配置文件，对所创建的网络进行描述

工作目录"/etc/cni/net.d"是CNI默认的网络配置文件目录，当没有特别指定时，CNI就会默认对该目录进行查找，从中加载配置文件进行容器网络的创建。现在我们只需要执行如下命令，描述一个我们想要创建的容器网络"mynet"即可。为了简单起见，我们的NetworkList中仅仅只有"mynet"这一个network。


```
$ mkdir -p /etc/cni/net.d
$ cat >/etc/cni/net.d/10-mynet.conflist <<EOF
{
        "cniVersion": "0.3.0",
        "name": "mynet",
        "plugins": [
          {
                "type": "bridge",
                "bridge": "cni0",
                "isGateway": true,
                "ipMasq": true,
                "ipam": {
                        "type": "host-local",
                        "subnet": "10.22.0.0/16",
                        "routes": [
                                { "dst": "0.0.0.0/0" }
                        ]
                }
          }
        ]
}
EOF
```
看下calico的配置cni配置：

```
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
```

3 模拟CNI的执行过程，创建network namespace，加入上文中描述的容器网络"mynet"


```
$ export CNI_PATH=$GOPATH/src/github.com/containernetworking/plugins/bin<br><br>$ ip netns add ns
```

 

```
$ ./cnitool add mynet /var/run/netns/ns
{
    "cniVersion": "0.3.0",
    "interfaces": [
        {
            "name": "cni0",
            "mac": "0a:58:0a:16:00:01"
        },
        {
            "name": "vetha418f787",
            "mac": "c6:e3:e9:1c:2f:20"
        },
        {
            "name": "eth0",
            "mac": "0a:58:0a:16:00:05",
            "sandbox": "/var/run/netns/ns"
        }
    ],
    "ips": [
        {
            "version": "4",
            "interface": 2,
            "address": "10.22.0.5/16",
            "gateway": "10.22.0.1"
        }
    ],
    "routes": [
        {
            "dst": "0.0.0.0/0"
        }
    ],
    "dns": {}
}
 
$ ip netns exec ns ifconfig
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.22.0.5  netmask 255.255.0.0  broadcast 0.0.0.0
        inet6 fe80::646e:89ff:fea6:f9b5  prefixlen 64  scopeid 0x20<link>
        ether 0a:58:0a:16:00:05  txqueuelen 0  (Ethernet)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 8  bytes 648 (648.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

## 3 CNI 是怎么实现的

1.加载容器网络配置信息


```
type NetworkConfigList struct {
    Name       string
    CNIVersion string
    Plugins    []*NetworkConfig
    Bytes      []byte
}
 
type NetworkConfig struct {
    Network *types.NetConf
    Bytes   []byte
}
 
// NetConf describes a network.
type NetConf struct {
    CNIVersion string `json:"cniVersion,omitempty"`
 
    Name         string          `json:"name,omitempty"`
    Type         string          `json:"type,omitempty"`
    Capabilities map[string]bool `json:"capabilities,omitempty"`
    IPAM         struct {
        Type string `json:"type,omitempty"`
    } `json:"ipam,omitempty"`
    DNS DNS `json:"dns"`
}
```

数据结构表示的内容和演示实例中的json配置文件基本是一致的。因此，这一步的源码实现很简单，基本流程如下：
1. 首先确定配置文件所在的目录netdir，如果没有特别指定，则默认为"/etc/cni/net.d"
2. 调用netconf, err := libcni.LoadConfList(netdir, os.Args[2])，其中参数os.Args[2]为用户指定的想要加入的network的名字，在演示示例中即为"mynet"。该函数首先会查找netdir中是否有以".conflist"作为后缀的配置文件，如果有，且配置信息中的"Name"和参数os.Args[2]一致，则直接用配置信息填充并返回NetConfigList即可。否则，查找是否存在以".conf"或".json"作为后缀的配置文件。同样，如果存在"Name"一致的配置，则加载该配置文件。由于".conf"或".json"中都是单个的网络配置，因此需要将其包装成仅有一个NetConfig的NetworkConfigList再返回。到此为止，容器网络配置加载完成。

2. 配置容器运行时信息


```
type RuntimeConf struct {
    ContainerID string
    NetNS       string
    IfName      string
    Args        [][2]string
    // A dictionary of capability-specific data passed by the runtime
    // to plugins as top-level keys in the 'runtimeConfig' dictionary
    // of the plugin's stdin data.  libcni will ensure that only keys
    // in this map which match the capabilities of the plugin are passed
    // to the plugin
    CapabilityArgs map[string]interface{}
}
```

最重要的字段无疑是"NetNS"，它指定了需要加入容器网络的network namespace路径。而Args字段和CapabilityArgs字段都是可选的，用于传递额外的配置信息。具体的内容参见上文中的配置说明。在上文的演示实例中，我们并没有对Args和CapabilityArgs进行任何的配置，为了简单起见，我们可以直接认为它们为空。因此，cnitool对RuntimeConf的配置也就极为简单了，只需要将参数指定的netns赋值给NetNS字段，而ContainerID和IfName字段随意赋值即可，默认将它们分别赋值为"cni"和"eth0"。

3. 加入容器网络

根据加载的容器网络配置信息和容器运行时信息，执行加入容器网络的操作，并将执行的结果打印输出


```
switch os.Args[1] {
case CmdAdd:
    result, err := cninet.AddNetworkList(netconf, rt)
    if result != nil {
        _ = result.Print()
    }
    exit(err)
    ......
}
```

AddNetworkList函数中


```
// AddNetworkList executes a sequence of plugins with the ADD command
func (c *CNIConfig) AddNetworkList(list *NetworkConfigList, rt *RuntimeConf) (types.Result, error) {
    var prevResult types.Result
    for _, net := range list.Plugins {
        pluginPath, err := invoke.FindInPath(net.Network.Type, c.Path)
                .....
        newConf, err := buildOneConfig(list, net, prevResult, rt)
                ......
        prevResult, err = invoke.ExecPluginWithResult(pluginPath, newConf.Bytes, c.args("ADD", rt))
                ......
    }
 
    return prevResult, nil
}
```
该函数的作用就是按顺序对NetworkList中的各个network执行ADD操作。该函数的执行过程也非常清晰，利用一个循环遍历NetworkList中的各个network，并对每个network进行如下三步操作：

首先，调用FindInPath函数，根据newtork的类型，在插件的存放路径，也就是上文中的CNI_PATH中查找是否存在对应插件的可执行文件。若存在则返回其绝对路径pluginPath
接着，调用buildOneConfig函数，从NetworkList中提取分离出当前执行ADD操作的network的NetworkConfig结构。这里特别需要注意的是preResult参数，它是上一个network的操作结果，也将被编码进NetworkConfig中。需要注意的是，当我们在执行NetworkList时，必须将前一个network的执行结果作为参数传递给当前正在进行执行的network。并且在buildOneConfig函数构建每个NetworkConfig时会默认将其中的"name"和"cniVersion"和NetworkList中的配置保持一致，从而避免冲突。

最后，调用invoke.ExecPluginWithResult(pluginPath, netConf.Bytes, c.args("ADD", rt))真正执行network的ADD操作。这里我们需要注意的是netConf.Bytes和c.args("ADD", rt)这两个参数。其中netConf.Bytes用于存放NetworkConfig中的NetConf结构以及例如上文中的prevResult进行json编码形成的字节流。而c.args()函数用于构建一个Args类型的实例，其中主要存储容器运行时信息，以及执行的CNI操作的信息，例如"ADD"或"DEL"，和插件的存储路径。
事实上ExecPluginWithResult仅仅是一个包装函数，它仅仅只是调用了函数defaultPluginExec.WithResult(pluginPath, netconf, args)之后，就直接返回了。


```
func (e *PluginExec) WithResult(pluginPath string, netconf []byte, args CNIArgs) (types.Result, error) {
    stdoutBytes, err := e.RawExec.ExecPlugin(pluginPath, netconf, args.AsEnv())
        .....
    // Plugin must return result in same version as specified in netconf
    versionDecoder := &version.ConfigDecoder{}
    confVersion, err := versionDecoder.Decode(netconf)
        ....
    return version.NewResult(confVersion, stdoutBytes)
}
```



首先调用e.RawExec.ExecPlugin(pluginPath, netconf, args.AsEnv())函数执行具体的CNI操作，对于它的具体内容，我们将在下文进行分析。此处需要注意的是它的第三个参数args.AsEnv()，该函数做的工作其实就是获取已有的环境变量，并且将args内的信息，例如CNI操作命令，以环境变量的形式保存起来，以例如"CNI_COMMAND=ADD"的形式传输给插件。由此我们可以知道，容器运行时信息、CNI操作命令以及插件存储路径都是以环境变量的形式传递给插件的
接着调用versionDecoder.Decode(netconf)从network配置中解析出CNI版本信息
最后，调用version.NewResult(confVersion, stdoutBytes)，根据CNI版本，构建相应的返回结果
最后，我们来看看e.RawExecPlugin函数是如何操作的，代码如下所示：


```
func (e *RawExec) ExecPlugin(pluginPath string, stdinData []byte, environ []string) ([]byte, error) {
    stdout := &bytes.Buffer{}
 
    c := exec.Cmd{
        Env:    environ,
        Path:   pluginPath,
        Args:   []string{pluginPath},
        Stdin:  bytes.NewBuffer(stdinData),
        Stdout: stdout,
        Stderr: e.Stderr,
    }
    if err := c.Run(); err != nil {
        return nil, pluginErr(err, stdout.Bytes())
    }
 
    return stdout.Bytes(), nil
}
```
这个理论上最为核心的函数却出乎意料的简单，它所做的工作仅仅只是exec了插件的可执行文件。话虽如此，我们仍然有以下几点需要注意：



容器运行时信息以及CNI操作命令等都是以环境变量的形式传递给插件的，这点在上文中已经有所提及
容器网络的配置信息是通过标准输入的形式传递给插件的
插件的运行结果是以标准输出的形式返回给CNI的


到此为止，整个CNI的执行流已经非常清楚了。简单地说，一个CNI插件就是一个可执行文件，我们从配置文件中获取network配置信息，从容器管理系统处获取运行时信息，再将前者以标准输入的形式，后者以环境变量的形式传递传递给插件，最终以配置文件中定义的顺序依次调用各个插件，并且将前一个插件的执行结果包含在network配置信息中传递给下一个执行的插件，整个过程就是这样。

## 4 k8s kubelet 如何调用CNI插件
kubelet 会调用RunPodSandbox方法：


```
Pull sandbox image(pause image)
Create the sandbox container
Create sandbox checkpoint.
Start the sandbox container
Setup networking for this sandbox, 主要调用SetUpPod
func (ds *dockerService) RunPodSandbox(ctx context.Context, r *runtimeapi.RunPodSandboxRequest) (*runtimeapi.RunPodSandboxResponse, error) {
   config := r.GetConfig()

   // Step 1: Pull the image for the sandbox.
   image := defaultSandboxImage
   podSandboxImage := ds.podSandboxImage
   if len(podSandboxImage) != 0 {
      image = podSandboxImage
   }

   // NOTE: To use a custom sandbox image in a private repository, users need to configure the nodes with credentials properly.
   // see: http://kubernetes.io/docs/user-guide/images/#configuring-nodes-to-authenticate-to-a-private-repository
   // Only pull sandbox image when it's not present - v1.PullIfNotPresent.
   if err := ensureSandboxImageExists(ds.client, image); err != nil {
      return nil, err
   }

   // Step 2: Create the sandbox container.
   if r.GetRuntimeHandler() != "" {
      return nil, fmt.Errorf("RuntimeHandler %q not supported", r.GetRuntimeHandler())
   }
   createConfig, err := ds.makeSandboxDockerConfig(config, image)
   if err != nil {
      return nil, fmt.Errorf("failed to make sandbox docker config for pod %q: %v", config.Metadata.Name, err)
   }
   createResp, err := ds.client.CreateContainer(*createConfig)
   if err != nil {
      createResp, err = recoverFromCreationConflictIfNeeded(ds.client, *createConfig, err)
   }

   if err != nil || createResp == nil {
      return nil, fmt.Errorf("failed to create a sandbox for pod %q: %v", config.Metadata.Name, err)
   }
   resp := &runtimeapi.RunPodSandboxResponse{PodSandboxId: createResp.ID}

   ds.setNetworkReady(createResp.ID, false)
   defer func(e *error) {
      // Set networking ready depending on the error return of
      // the parent function
      if *e == nil {
         ds.setNetworkReady(createResp.ID, true)
      }
   }(&err)

   // Step 3: Create Sandbox Checkpoint.
   if err = ds.checkpointManager.CreateCheckpoint(createResp.ID, constructPodSandboxCheckpoint(config)); err != nil {
      return nil, err
   }

   // Step 4: Start the sandbox container.
   // Assume kubelet's garbage collector would remove the sandbox later, if
   // startContainer failed.
   err = ds.client.StartContainer(createResp.ID)
   if err != nil {
      return nil, fmt.Errorf("failed to start sandbox container for pod %q: %v", config.Metadata.Name, err)
   }

   // Rewrite resolv.conf file generated by docker.
   // NOTE: cluster dns settings aren't passed anymore to docker api in all cases,
   // not only for pods with host network: the resolver conf will be overwritten
   // after sandbox creation to override docker's behaviour. This resolv.conf
   // file is shared by all containers of the same pod, and needs to be modified
   // only once per pod.
   if dnsConfig := config.GetDnsConfig(); dnsConfig != nil {
      containerInfo, err := ds.client.InspectContainer(createResp.ID)
      if err != nil {
         return nil, fmt.Errorf("failed to inspect sandbox container for pod %q: %v", config.Metadata.Name, err)
      }

      if err := rewriteResolvFile(containerInfo.ResolvConfPath, dnsConfig.Servers, dnsConfig.Searches, dnsConfig.Options); err != nil {
         return nil, fmt.Errorf("rewrite resolv.conf failed for pod %q: %v", config.Metadata.Name, err)
      }
   }

   // Do not invoke network plugins if in hostNetwork mode.
   if config.GetLinux().GetSecurityContext().GetNamespaceOptions().GetNetwork() == runtimeapi.NamespaceMode_NODE {
      return resp, nil
   }

   // Step 5: Setup networking for the sandbox.
   // All pod networking is setup by a CNI plugin discovered at startup time.
   // This plugin assigns the pod ip, sets up routes inside the sandbox,
   // creates interfaces etc. In theory, its jurisdiction ends with pod
   // sandbox networking, but it might insert iptables rules or open ports
   // on the host as well, to satisfy parts of the pod spec that aren't
   // recognized by the CNI standard yet.
   cID := kubecontainer.BuildContainerID(runtimeName, createResp.ID)
   networkOptions := make(map[string]string)
   if dnsConfig := config.GetDnsConfig(); dnsConfig != nil {
      // Build DNS options.
      dnsOption, err := json.Marshal(dnsConfig)
      if err != nil {
         return nil, fmt.Errorf("failed to marshal dns config for pod %q: %v", config.Metadata.Name, err)
      }
      networkOptions["dns"] = string(dnsOption)
   }
   err = ds.network.SetUpPod(config.GetMetadata().Namespace, config.GetMetadata().Name, cID, config.Annotations, networkOptions)
   if err != nil {
      errList := []error{fmt.Errorf("failed to set up sandbox container %q network for pod %q: %v", createResp.ID, config.Metadata.Name, err)}

      // Ensure network resources are cleaned up even if the plugin
      // succeeded but an error happened between that success and here.
      err = ds.network.TearDownPod(config.GetMetadata().Namespace, config.GetMetadata().Name, cID)
      if err != nil {
         errList = append(errList, fmt.Errorf("failed to clean up sandbox container %q network for pod %q: %v", createResp.ID, config.Metadata.Name, err))
      }

      err = ds.client.StopContainer(createResp.ID, defaultSandboxGracePeriod)
      if err != nil {
         errList = append(errList, fmt.Errorf("failed to stop sandbox container %q for pod %q: %v", createResp.ID, config.Metadata.Name, err))
      }

      return resp, utilerrors.NewAggregate(errList)
   }

   return resp, nil
}
```

再看SetUpPod这个函数


```
kubernetes/pkg/kubelet/dockershim/network/cni/cni.go (SetUpPod())

根据容器id 拿到netnsPath
调用plugin.addToNetwork
func (plugin *cniNetworkPlugin) SetUpPod(namespace string, name string, id kubecontainer.ContainerID, annotations, options map[string]string) error {
   if err := plugin.checkInitialized(); err != nil {
      return err
   }
	
   netnsPath, err := plugin.host.GetNetNS(id.ID)
   if err != nil {
      return fmt.Errorf("CNI failed to retrieve network namespace path: %v", err)
   }

   // Windows doesn't have loNetwork. It comes only with Linux
   if plugin.loNetwork != nil {
      if _, err = plugin.addToNetwork(plugin.loNetwork, name, namespace, id, netnsPath, annotations, options); err != nil {
         return err
      }
   }

   _, err = plugin.addToNetwork(plugin.getDefaultNetwork(), name, namespace, id, netnsPath, annotations, options)
   return err
}
```

再看addToNetwork:


```
生成CNI network的conf配置，、
然后调用cniNet.AddNetworkList(netConf, rt)，这个AddNetworkList就是CNI Lib也就是上面所讲的。最终调用cni的bin文件，通过环境变量传入参数。
func (plugin *cniNetworkPlugin) addToNetwork(network *cniNetwork, podName string, podNamespace string, podSandboxID kubecontainer.ContainerID, podNetnsPath string, annotations, options map[string]string) (cnitypes.Result, error) {
   rt, err := plugin.buildCNIRuntimeConf(podName, podNamespace, podSandboxID, podNetnsPath, annotations, options)
   if err != nil {
      klog.Errorf("Error adding network when building cni runtime conf: %v", err)
      return nil, err
   }

   pdesc := podDesc(podNamespace, podName, podSandboxID)
   netConf, cniNet := network.NetworkConfig, network.CNIConfig
   klog.V(4).Infof("Adding %s to network %s/%s netns %q", pdesc, netConf.Plugins[0].Network.Type, netConf.Name, podNetnsPath)
   res, err := cniNet.AddNetworkList(netConf, rt)
   if err != nil {
      klog.Errorf("Error adding %s to network %s/%s: %v", pdesc, netConf.Plugins[0].Network.Type, netConf.Name, err)
      return nil, err
   }
   klog.V(4).Infof("Added %s to network %s: %v", pdesc, netConf.Name, res)
   return res, nil
}
```

CNI的接口是：github.com/containernetworking/cni/libcni/api.go


```
type CNI interface {
   AddNetworkList(net *NetworkConfigList, rt *RuntimeConf) (types.Result, error)
   DelNetworkList(net *NetworkConfigList, rt *RuntimeConf) error

   AddNetwork(net *NetworkConfig, rt *RuntimeConf) (types.Result, error)
   DelNetwork(net *NetworkConfig, rt *RuntimeConf) error
}
```

## 5 参考
https://github.com/feiskyer/kubernetes-handbook/blob/master/network/calico/index.md

http://www.cnblogs.com/YaoDD/p/7419383.html


