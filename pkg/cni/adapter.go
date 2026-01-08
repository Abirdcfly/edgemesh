//go:build linux
// +build linux

package cni

import (
	"context"
	"fmt"
	"net"
	"os"
	"sync/atomic"
	"time"

	"github.com/kubeedge/edgemesh/pkg/util"
	utilipset "github.com/kubeedge/edgemesh/pkg/util/ipset"
	"github.com/vishvananda/netlink"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
	utiliptables "k8s.io/kubernetes/pkg/util/iptables"
	"k8s.io/utils/exec"

	"github.com/kubeedge/edgemesh/pkg/apis/config/defaults"
	"github.com/kubeedge/edgemesh/pkg/apis/config/v1alpha1"
	"github.com/kubeedge/edgemesh/pkg/tunnel"
	"github.com/kubeedge/edgemesh/pkg/util/tunutils"
)

const (
	AllNodeIPs  = "kubeedge-node"      // 边缘节点需要转发到全部节点
	EdgeNodeIPs = "kubeedge-edge-node" // 云端节点存在CNI，只需要转发到边缘节点
)

type Adapter interface {
	// HandleReceive deal with data from Pod to Tunnel
	TunToTunnel()

	// WatchRoute watch CIDR in overlayNetwork and insert Route to Tun dev
	WatchRoute() error

	// CloseRoute close all the Tun and stream
	CloseRoute()
}

var _ Adapter = (*MeshAdapter)(nil)

type MeshAdapter struct {
	kubeClient       clientset.Interface
	IptInterface     utiliptables.Interface
	IpsetInterface   utilipset.Interface
	execer           exec.Interface
	ConfigSyncPeriod time.Duration
	TunConn          *cni.TunConn
	HostCIDR         string
	Cloud            []string      // PodCIDR in cloud
	Edge             []string      // PodCIDR in edge
	Close            chan struct{} // stop signal
	nodeSynced       int32
	setName          string
	mode             defaults.RunningMode
}

func NewMeshAdapter(cfg *v1alpha1.EdgeCNIConfig, cli clientset.Interface) (*MeshAdapter, error) {
	// get pod network info from cfg and APIServer
	cloud, edge, err := getCIDR(cfg.MeshCIDRConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to get CIDR from config, error: %v", err)
	}
	klog.Infof("the cloud CIDRs are %v, the edge CIDRs are %v", cloud, edge)

	local, err := findLocalCIDR(cli)
	if err != nil {
		return nil, fmt.Errorf("failed to get local CIDR from apiserver, error: %v", err)
	}
	klog.Infof("local CIDR is %v", local)

	// Create a iptables utils.
	execer := exec.New()
	iptIf := utiliptables.New(execer, utiliptables.ProtocolIPv4)

	// create a tun Connection stream
	tun, err := cni.NewTunConn(defaults.TunDeviceName)
	if err != nil {
		return nil, fmt.Errorf("failed to create tun device %s, error: %v", defaults.TunDeviceName, err)
	}
	// setup tun and check it from ifconfig or ip link
	err = cni.SetupTunDevice(defaults.TunDeviceName)
	if err != nil {
		return nil, fmt.Errorf("failed to set up tun device %s, error: %v", defaults.TunDeviceName, err)
	}

	ipsetIf := utilipset.New(exec.New())
	setName := EdgeNodeIPs
	mode := v1alpha1.DetectRunningMode()
	if mode == defaults.EdgeMode {
		setName = AllNodeIPs
	}
	nodeIPSet := &utilipset.IPSet{
		Name:       setName,
		SetType:    utilipset.Type("hash:ip"),
		HashFamily: utilipset.ProtocolFamilyIPV4,
		Comment:    "kubeedge forwards the traffic to the node ip",
	}
	if err = ipsetIf.CreateSet(nodeIPSet, true); err != nil {
		return nil, fmt.Errorf("failed to create ipset %s, error: %v", nodeIPSet.Name, err)
	}

	return &MeshAdapter{
		kubeClient:     cli,
		IptInterface:   iptIf,
		TunConn:        tun,
		HostCIDR:       local,
		Edge:           edge,
		Cloud:          cloud,
		IpsetInterface: ipsetIf,
		setName:        setName,
		mode:           mode,
	}, nil
}

// getCIDR read from config file and get edge/cloud cidr user set
func getCIDR(cfg *v1alpha1.MeshCIDRConfig) ([]string, []string, error) {
	cloud := cfg.CloudCIDR
	edge := cfg.EdgeCIDR

	if err := validateCIDRs(cloud); err != nil {
		return nil, nil, fmt.Errorf("cloud CIDRs are invalid, error: %v", err)
	}

	if err := validateCIDRs(edge); err != nil {
		return nil, nil, fmt.Errorf("edge CIDRs are invalid, error: %v", err)
	}

	return cloud, edge, nil
}

// check if the address validate
func validateCIDRs(cidrs []string) error {
	for _, cidr := range cidrs {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return fmt.Errorf("invalid CIDR %s: %w", cidr, err)
		}
	}
	return nil
}

// get Local Pod CIDR
func findLocalCIDR(cli clientset.Interface) (string, error) {
	nodeName := os.Getenv("NODE_NAME")
	if nodeName == "" {
		return "", fmt.Errorf("the env NODE_NAME is not set")
	}

	// use clientset to get local info
	node, err := cli.CoreV1().Nodes().Get(context.Background(), nodeName, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("failed to get Node %s, error: %v", nodeName, err)
	}
	podCIDR := node.Spec.PodCIDR
	if podCIDR == "" {
		podCIDR = node.Annotations["kubeedge.io/pod-cidr-ipv4"]
	}
	return podCIDR, nil
}

// CheckTunCIDR check whether the mesh CIDR and the given parameter CIDR are in the same network or not.
func (mesh *MeshAdapter) CheckTunCIDR(outerCidr string) (bool, error) {
	outerIP, outerNet, err := net.ParseCIDR(outerCidr)
	if err != nil {
		return false, fmt.Errorf("failed to parse outerCIDR %s, error:%v", outerCidr, err)
	}

	_, hostNet, err := net.ParseCIDR(mesh.HostCIDR)
	if err != nil {
		return false, fmt.Errorf("failed to parse hostCIDR %s, error: %v", mesh.HostCIDR, err)
	}

	return hostNet.Contains(outerIP) && hostNet.Mask.String() == outerNet.Mask.String(), nil
}

func (mesh *MeshAdapter) Run() {
	klog.Infof("[CNI] Start Meshadapter")
	// get data from receive pipeline
	go mesh.TunToTunnel()

	kubeInformerFactory := informers.NewSharedInformerFactory(mesh.kubeClient, mesh.ConfigSyncPeriod)
	nodesInformer := kubeInformerFactory.Core().V1().Nodes()
	nodesInformer.Informer().AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc:    mesh.handleAddNodes,
			UpdateFunc: mesh.handleUpdateNodes,
			DeleteFunc: mesh.handleDeleteNodes,
		},
		mesh.ConfigSyncPeriod,
	)
	go mesh.runNodes(nodesInformer.Informer().HasSynced, mesh.Close)
	kubeInformerFactory.Start(mesh.Close)
}

func (mesh *MeshAdapter) WatchRoute() error {
	if mesh.mode == defaults.CloudMode {
		for _, cidr := range mesh.Edge {
			err := cni.AddRouteToTun(cidr, defaults.TunDeviceName)
			if err != nil {
				klog.Errorf("failed to add route to TunDev, error: %v", err)
				continue
			}
		}
		for _, cidr := range mesh.Cloud {
			// Insert IPtable rule to make sure Other CNIs do not make SNAT
			_, err := mesh.IptInterface.EnsureRule(utiliptables.Prepend, utiliptables.TableNAT, utiliptables.ChainPostrouting, "-s", cidr, "-o", defaults.TunDeviceName, "-j", "ACCEPT")
			if err != nil {
				klog.Errorf("fail to insert iptables rule:-I nat POSTROUTING -s %s -o %s -j ACCEPT, error: %v", cidr, defaults.TunDeviceName, err)
				return fmt.Errorf("failed to insert iptable rule, error: %v", err)
			}

			_, err = mesh.IptInterface.EnsureRule(utiliptables.Prepend, utiliptables.TableMangle, utiliptables.ChainPrerouting, "-s", cidr, "-m", "set", "--match-set", mesh.setName, "dst", "-m", "mark", "--mark", "0x0", "-j", "MARK", "--set-mark", "0x89")
			if err != nil {
				klog.Errorf("fail to insert iptables rule:-I mangle PREROUTING -s %s -m set --match-set %s dst -m mark --mark 0x0 -j MARK --set-mark 0x89, error: %v", cidr, mesh.setName, err)
				return fmt.Errorf("failed to insert iptable rule, error: %v", err)
			}
		}
		// Configure node destination routes for traffic routing
		if err := mesh.configureNodeDstRoutes(); err != nil {
			return fmt.Errorf("failed to configure node dst routes, error: %v", err)
		}
		return nil
	}
	// insert basic route to Tundev
	allCIDR := append(mesh.Edge, mesh.Cloud...)
	for _, cidr := range allCIDR {
		sameNet, err := mesh.CheckTunCIDR(cidr)
		if err != nil {
			return fmt.Errorf("failed to check whether CIDRs are in the same network or not, error: %v", err)
		}
		if !sameNet {
			err = cni.AddRouteToTun(cidr, defaults.TunDeviceName)
			if err != nil {
				klog.Errorf("failed to add route to TunDev, error: %v", err)
				continue
			}
		}
	}
	// Insert IPtable rule to make sure Other CNIs do not make SNAT
	_, err := mesh.IptInterface.EnsureRule(utiliptables.Prepend, utiliptables.TableNAT, utiliptables.ChainPostrouting, "-s", mesh.HostCIDR, "-o", defaults.TunDeviceName, "-j", "ACCEPT")
	if err != nil {
		klog.Errorf("fail to insert iptables rule:-I nat POSTROUTING -s %s -o %s -j ACCEPT, error: %v", mesh.HostCIDR, defaults.TunDeviceName, err)
		return fmt.Errorf("failed to insert iptable rule, error: %v", err)
	}

	_, err = mesh.IptInterface.EnsureRule(utiliptables.Prepend, utiliptables.TableMangle, utiliptables.ChainPrerouting, "-s", mesh.HostCIDR, "-m", "set", "--match-set", mesh.setName, "dst", "-m", "mark", "--mark", "0x0", "-j", "MARK", "--set-mark", "0x89")
	if err != nil {
		klog.Errorf("fail to insert iptables rule:-I mangle PREROUTING -s %s -m set --match-set %s dst -m mark --mark 0x0 -j MARK --set-mark 0x89, error: %v", mesh.HostCIDR, mesh.setName, err)
		return fmt.Errorf("failed to insert iptable rule, error: %v", err)
	}

	// Configure node destination routes for traffic routing
	if err := mesh.configureNodeDstRoutes(); err != nil {
		return fmt.Errorf("failed to configure node dst routes, error: %v", err)
	}

	return nil
	// TODO： watch the subNetwork event and if the cidr changes ,apply that change to node
}

func (mesh *MeshAdapter) TunToTunnel() {
	// Listen at TunDev and Receive data to TunConn Buffer
	go mesh.TunConn.TunReceiveLoop()
	go mesh.HandleReceiveFromTun()
}

func (mesh *MeshAdapter) HandleReceiveFromTun() {
	buffer := cni.NewRecycleByteBuffer(cni.PacketSize)
	tun := mesh.TunConn
	for {
		select {
		case <-mesh.Close:
			klog.Warningln("Close HandleReceive Process")
			return
		case packet := <-tun.ReceivePipe:
			//set CNI Options
			n := len(packet)
			buffer.Write(packet[:n])
			frame, err := cni.ParseIPFrame(buffer)
			if err != nil {
				klog.Errorf("failed to parse IP frame, error: %v", err)
				continue
			}

			nodeName, err := mesh.GetNodeNameByPodIP(frame.GetTargetIP())
			if err != nil {
				klog.Errorf("failed to get NodeName by PodIP %s, error: %v", frame.GetTargetIP(), err)
				continue
			}
			klog.Infof("find node %s by Pod IP %s", nodeName, frame.GetTargetIP())

			cniOpts := tunnel.ProxyOptions{
				Protocol: frame.GetProtocol(),
				NodeName: nodeName,
			}
			stream, err := tunnel.Agent.GetCNIAdapterStream(cniOpts)
			if err != nil {
				klog.Errorf("l3 adapter failed to get proxy stream from %s, error: %v", cniOpts.NodeName, err)
				continue
			}
			_, err = stream.Write(frame.ToBytes())
			if err != nil {
				klog.Errorf("failed to write stream data, error: %v", err)
				continue
			}
			klog.Infof("send Data to %s", frame.GetTargetIP())
			klog.Infof("l3 adapter start proxy data between nodes %v", cniOpts.NodeName)
			klog.Infof("Success proxy to %v", tun)
		}
	}
}

func (mesh *MeshAdapter) GetNodeNameByPodIP(podIP string) (string, error) {
	// use FieldSelector to get Pod Name
	pods, err := mesh.kubeClient.CoreV1().Pods("").List(context.Background(), metav1.ListOptions{
		FieldSelector: "status.podIP=" + podIP,
	})
	if err != nil {
		return "", err
	}

	if len(pods.Items) == 0 {
		return "", fmt.Errorf("no pod found with IP %s", podIP)
	}

	return pods.Items[0].Spec.NodeName, nil
}

func (mesh *MeshAdapter) CloseRoute() {
	close(mesh.Close)
	err := mesh.TunConn.CleanTunRoute()
	if err != nil {
		klog.Errorf("failed to clean tun route, error: %v", err)
	}
	err = mesh.TunConn.CleanTunDevice()
	if err != nil {
		klog.Errorf("failed to clean tun device, error: %v", err)
	}
	err = mesh.IpsetInterface.DestroySet(mesh.setName)
	if err != nil {
		klog.Errorf("failed to destroy set:%s, error: %v", mesh.setName, err)
	}
	// Clean up node dst routes
	err = mesh.cleanupNodeDstRoutes()
	if err != nil {
		klog.Errorf("failed to cleanup node dst routes, error: %v", err)
	}
}

func (mesh *MeshAdapter) runNodes(listerSynced cache.InformerSynced, stopCh <-chan struct{}) {
	klog.InfoS("Starting cni nodes controller")

	if !cache.WaitForNamedCacheSync("cni nodes", stopCh, listerSynced) {
		return
	}
	mesh.OnNodesSynced()
}

func (mesh *MeshAdapter) handleAddNodes(obj interface{}) {
	node, ok := obj.(*v1.Node)
	if !ok {
		klog.Errorf("failed to convert %v to Node", obj)
		return
	}

	// Cloud mode: only add edge nodes
	if mesh.mode == defaults.CloudMode && !util.IsEdgeNode(node) {
		return
	}

	// Edge mode: exclude self node
	if mesh.mode == defaults.EdgeMode {
		nodeName := os.Getenv("NODE_NAME")
		if nodeName != "" && node.Name == nodeName {
			klog.V(2).Infof("Skipping self node %s in ipset", node.Name)
			return
		}
	}

	set := &utilipset.IPSet{Name: mesh.setName}
	err := mesh.IpsetInterface.AddEntry(util.GetNodeIP(node), set, true)
	if err != nil {
		klog.Errorf("failed to EnsureEntry %s: %v", node.Name, err)
		return
	}
}

func (mesh *MeshAdapter) handleUpdateNodes(oldObj interface{}, newObj interface{}) {
	node, ok := newObj.(*v1.Node)
	if !ok {
		klog.Errorf("failed to convert %v to Node", newObj)
		return
	}

	// Edge mode: exclude self
	if mesh.mode == defaults.EdgeMode {
		nodeName := os.Getenv("NODE_NAME")
		if nodeName != "" && node.Name == nodeName {
			return
		}
	}

	if mesh.mode == defaults.CloudMode {
		if !util.IsEdgeNode(node) {
			exist, err := mesh.IpsetInterface.TestEntry(util.GetNodeIP(node), mesh.setName)
			if err != nil {
				klog.Errorf("failed to CheckEntry %s: %v", node.Name, err)
				return
			}
			if exist {
				err = mesh.IpsetInterface.DelEntry(util.GetNodeIP(node), mesh.setName)
				if err != nil {
					klog.Errorf("failed to DeleteEntry %s: %v", node.Name, err)
					return
				}
			}
			return
		}
	}
	set := &utilipset.IPSet{Name: mesh.setName}
	err := mesh.IpsetInterface.AddEntry(util.GetNodeIP(node), set, true)
	if err != nil {
		klog.Errorf("failed to EnsureEntry %s: %v", node.Name, err)
		return
	}
}

func (mesh *MeshAdapter) handleDeleteNodes(obj interface{}) {
	node, ok := obj.(*v1.Node)
	if !ok {
		klog.Errorf("failed to convert %v to Node", obj)
		return
	}

	// Edge mode: skip self deletion (since it was never added)
	if mesh.mode == defaults.EdgeMode {
		nodeName := os.Getenv("NODE_NAME")
		if nodeName != "" && node.Name == nodeName {
			klog.V(2).Infof("Skipping self node %s deletion", node.Name)
			return
		}
	}

	exist, err := mesh.IpsetInterface.TestEntry(util.GetNodeIP(node), mesh.setName)
	if err != nil {
		klog.Errorf("failed to CheckEntry %s: %v", node.Name, err)
		return
	}
	if exist {
		err = mesh.IpsetInterface.DelEntry(util.GetNodeIP(node), mesh.setName)
		if err != nil {
			klog.Errorf("failed to DeleteEntry %s: %v", node.Name, err)
			return
		}
	}
}

func (mesh *MeshAdapter) OnNodesSynced() {
	klog.V(2).InfoS("CNI OnNodesSynced")
	atomic.StoreInt32(&mesh.nodeSynced, 1)
	// Must sync from a goroutine to avoid blocking the
	// node event handler on startup with large numbers
	// of initial objects
	go mesh.syncNodes()
}

func (mesh *MeshAdapter) syncNodes() {
	start := time.Now()
	defer func() {
		klog.V(4).InfoS("syncNodes complete", "elapsed", time.Since(start))
	}()

	// don't sync rules till we've received services and endpoints
	if mesh.nodeSynced < 1 {
		klog.V(2).InfoS("Not syncing nodes until cache is ready")
		return
	}

	// Get all nodes from API server
	nodes, err := mesh.kubeClient.CoreV1().Nodes().List(context.Background(), metav1.ListOptions{})
	if err != nil {
		klog.Errorf("failed to list nodes for sync: %v", err)
		return
	}

	nodeName := os.Getenv("NODE_NAME")
	set := &utilipset.IPSet{Name: mesh.setName}
	syncedCount := 0

	for _, node := range nodes.Items {
		// Cloud mode: only add edge nodes
		if mesh.mode == defaults.CloudMode && !util.IsEdgeNode(&node) {
			continue
		}

		// Edge mode: exclude self
		if mesh.mode == defaults.EdgeMode && nodeName != "" && node.Name == nodeName {
			klog.V(2).Infof("Skipping self node %s during sync", node.Name)
			continue
		}

		// Add to ipset (idempotent)
		if err := mesh.IpsetInterface.AddEntry(util.GetNodeIP(&node), set, true); err != nil {
			klog.Errorf("failed to add node %s to ipset: %v", node.Name, err)
			continue
		}
		syncedCount++
		klog.V(2).Infof("Added node %s to ipset %s", node.Name, mesh.setName)
	}

	klog.Infof("Synced %d nodes to ipset %s", syncedCount, mesh.setName)
}

// ip rule add fwmark 0x89/0xffffffff table 89
// ip route add default dev edge_tun0 table 89
func (mesh *MeshAdapter) configureNodeDstRoutes() error {
	handle, err := netlink.NewHandle()
	if err != nil {
		return fmt.Errorf("failed to create netlink handle: %v", err)
	}
	defer handle.Close()

	// 1. Add ip rule: fwmark 0x89/0xffffffff table 89
	mask := uint32(0xffffffff)
	rule := &netlink.Rule{
		Family:            netlink.FAMILY_V4,
		Priority:          1000,
		Mark:              0x89,
		Mask:              &mask,
		Table:             89,
		Goto:              -1,
		Flow:              -1,
		SuppressPrefixlen: -1,
		SuppressIfgroup:   -1,
	}

	// Check if rule already exists
	rules, err := handle.RuleList(netlink.FAMILY_V4)
	if err != nil {
		return fmt.Errorf("failed to list rules: %v", err)
	}

	ruleExists := false
	for _, r := range rules {
		if r.Mark == rule.Mark && r.Table == rule.Table && r.Priority == rule.Priority {
			// Check mask if it's set
			if rule.Mask != nil && r.Mask != nil && *rule.Mask == *r.Mask {
				klog.V(4).Infof("Skipping rule %s because it matches the mask", r.String())
				ruleExists = true
				break
			} else if rule.Mask == nil && r.Mask == nil {
				klog.V(4).Infof("Skipping rule %s because it matches the mask", r.String())
				ruleExists = true
				break
			}
		}
		klog.V(5).Infof("has rule %s|%#v", r.String(), r)
		// has rule 32764: from all to all table 19
		// netlink.Rule{Priority:32764, Family:2, Table:19, Mark:0x19, Mask:(*uint32)(0x400077d9a8), Tos:0x0, TunID:0x0, Goto:-1, Src:(*net.IPNet)(nil), Dst:(*net.IPNet)(nil), Flow:-1, IifName:"", OifName:"", SuppressIfgroup:-1, SuppressPrefixlen:-1, Invert:false, Dport:(*netlink.RulePortRange)(nil), Sport:(*netlink.SulePortRange)(nil), IPProto:0, UIDRange:(*netlink.RuleUIDRange)(nil), Protocol:0x0, Type:0x0}
	}

	if !ruleExists {
		klog.V(5).Infof("want to add rule %s|%#v", rule.String(), rule)
		if err := handle.RuleAdd(rule); err != nil {
			return fmt.Errorf("failed to add rule: %v", err)
		}
		klog.Infof("Added ip rule: fwmark 0x%x/%d table %d", rule.Mark, *rule.Mask, rule.Table)
	} else {
		klog.V(2).Infof("Ip rule already exists: fwmark 0x%x/%d table %d", rule.Mark, *rule.Mask, rule.Table)
	}

	// 2. Add route: default dev edge_tun0 table 89
	link, err := netlink.LinkByName(defaults.TunDeviceName)
	if err != nil {
		return fmt.Errorf("failed to get %s: %v", defaults.TunDeviceName, err)
	}

	// default route = 0.0.0.0/0
	defaultDst := &net.IPNet{
		IP:   net.IPv4zero,
		Mask: net.CIDRMask(0, 32),
	}

	route := &netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       defaultDst,
		Table:     89,
	}

	// Check if route already exists
	routes, err := handle.RouteListFiltered(netlink.FAMILY_V4, route, netlink.RT_FILTER_TABLE)
	if err != nil {
		return fmt.Errorf("failed to list routes: %v", err)
	}

	routeExists := false
	for _, r := range routes {
		if r.LinkIndex == route.LinkIndex && r.Table == route.Table && r.Dst != nil && r.Dst.IP.Equal(net.IPv4zero) {
			routeExists = true
			break
		}
		klog.V(5).Infof("has route:%s|%#v", r.String(), r)
		// has route:
	}

	if !routeExists {
		klog.V(5).Infof("want to add route:%s|%#v", route.String(), route)
		if err := handle.RouteAdd(route); err != nil {
			return fmt.Errorf("failed to add route: %v", err)
		}
		klog.Infof("Added default route via %s in table %d", defaults.TunDeviceName, route.Table)
	} else {
		klog.V(2).Infof("Route already exists: default via %s table %d", defaults.TunDeviceName, route.Table)
	}

	return nil
}

// cleanupNodeDstRoutes removes the ip rule and route added by configureNodeDstRoutes
// ip rule del fwmark 0x89/0xffffffff table 89
// ip route del default dev edge_tun0 table 89
func (mesh *MeshAdapter) cleanupNodeDstRoutes() error {
	handle, err := netlink.NewHandle()
	if err != nil {
		return fmt.Errorf("failed to create netlink handle: %v", err)
	}
	defer handle.Close()

	// 1. Delete ip rule
	mask := uint32(0xffffffff)
	rule := &netlink.Rule{
		Priority: 1000,
		Mark:     0x89,
		Mask:     &mask,
		Table:    89,
	}

	// Check if rule exists before deleting
	rules, err := handle.RuleList(netlink.FAMILY_V4)
	if err != nil {
		return fmt.Errorf("failed to list rules: %v", err)
	}

	ruleExists := false
	for _, r := range rules {
		if r.Mark == rule.Mark && r.Table == rule.Table && r.Priority == rule.Priority {
			if rule.Mask != nil && r.Mask != nil && *rule.Mask == *r.Mask {
				ruleExists = true
				break
			} else if rule.Mask == nil && r.Mask == nil {
				ruleExists = true
				break
			}
		}
	}

	if ruleExists {
		if err := handle.RuleDel(rule); err != nil {
			return fmt.Errorf("failed to delete rule: %v", err)
		}
		klog.Infof("Deleted ip rule: fwmark 0x%x/%d table %d", rule.Mark, *rule.Mask, rule.Table)
	} else {
		klog.V(2).Infof("Ip rule does not exist: fwmark 0x%x/%d table %d", rule.Mark, *rule.Mask, rule.Table)
	}

	// 2. Delete route
	link, err := netlink.LinkByName(defaults.TunDeviceName)
	if err != nil {
		// If tun device doesn't exist, route is already gone
		klog.V(2).Infof("Tun device %s not found, route already cleaned", defaults.TunDeviceName)
		return nil
	}

	route := &netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       nil,
		Table:     89,
	}

	// Check if route exists before deleting
	routes, err := handle.RouteListFiltered(netlink.FAMILY_V4, route, netlink.RT_FILTER_TABLE)
	if err != nil {
		return fmt.Errorf("failed to list routes: %v", err)
	}

	routeExists := false
	for _, r := range routes {
		if r.LinkIndex == route.LinkIndex && r.Table == route.Table && r.Dst == nil {
			routeExists = true
			break
		}
	}

	if routeExists {
		if err := handle.RouteDel(route); err != nil {
			return fmt.Errorf("failed to delete route: %v", err)
		}
		klog.Infof("Deleted default route via %s in table %d", defaults.TunDeviceName, route.Table)
	} else {
		klog.V(2).Infof("Route does not exist: default via %s table %d", defaults.TunDeviceName, route.Table)
	}

	return nil
}
