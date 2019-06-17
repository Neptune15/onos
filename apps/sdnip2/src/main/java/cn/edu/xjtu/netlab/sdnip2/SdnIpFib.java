/*
 * Copyright 2015-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package cn.edu.xjtu.netlab.sdnip2;

import cn.edu.xjtu.netlab.sdnip2.config.SdnIpConfig;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Sets;
import org.onlab.packet.*;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.intentsync.IntentSynchronizationService;
import org.onosproject.net.*;
import org.onosproject.net.config.NetworkConfigEvent;
import org.onosproject.net.config.NetworkConfigListener;
import org.onosproject.net.config.NetworkConfigService;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.flowobjective.DefaultForwardingObjective;
import org.onosproject.net.flowobjective.FlowObjectiveService;
import org.onosproject.net.flowobjective.ForwardingObjective;
import org.onosproject.net.host.HostService;
import org.onosproject.net.intent.*;
import org.onosproject.net.intent.constraint.EncapsulationConstraint;
import org.onosproject.net.intent.constraint.PartialFailureConstraint;
import org.onosproject.net.intf.Interface;
import org.onosproject.net.intf.InterfaceEvent;
import org.onosproject.net.intf.InterfaceListener;
import org.onosproject.net.intf.InterfaceService;
import org.onosproject.net.packet.*;
import org.onosproject.net.topology.TopologyService;
import org.onosproject.routeservice.ResolvedRoute;
import org.onosproject.routeservice.RouteEvent;
import org.onosproject.routeservice.RouteListener;
import org.onosproject.routeservice.RouteService;
import org.osgi.service.component.annotations.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.ByteBuffer;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

import static org.onosproject.net.EncapsulationType.NONE;

/**
 * FIB component of SDN-IP.
 */
@Component(immediate = true, enabled = false)
public class SdnIpFib {
    private Logger log = LoggerFactory.getLogger(getClass());

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected InterfaceService interfaceService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected IntentSynchronizationService intentSynchronizer;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected NetworkConfigService networkConfigService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected RouteService routeService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PacketService packetService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected TopologyService topologyService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected IntentService intentService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowObjectiveService flowObjectiveService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected HostService hostService;

    private final InternalRouteListener routeListener = new InternalRouteListener();
    private final InternalInterfaceListener interfaceListener = new InternalInterfaceListener();
    private final InternalNetworkConfigListener networkConfigListener =
            new InternalNetworkConfigListener();

    private static final int PRIORITY_OFFSET = 100;
    private static final int PRIORITY_MULTIPLIER = 5;
    protected static final ImmutableList<Constraint> CONSTRAINTS
            = ImmutableList.of(new PartialFailureConstraint());

    private final Map<IpPrefix, MultiPointToSinglePointIntent> routeIntents
            = new ConcurrentHashMap<>();

    private final Map<IpPrefix, List<Object>> gateInfo
            = new ConcurrentHashMap<>();

    private ReactivePacketProcessor processor = new ReactivePacketProcessor();

    private ApplicationId appId;

    private static String CHANGE_DST = "I want watermelon";

    @Activate
    public void activate() {
        appId = coreService.getAppId(SdnIp.SDN_IP_APP);
        interfaceService.addListener(interfaceListener);
        networkConfigService.addListener(networkConfigListener);
        routeService.addListener(routeListener);

        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        selector.matchEthType(Ethernet.TYPE_IPV4);
        packetService.requestPackets(selector.build(), PacketPriority.REACTIVE, appId);
        packetService.addProcessor(processor, PacketProcessor.ADVISOR_MAX + 1);
    }

    @Deactivate
    public void deactivate() {
        interfaceService.removeListener(interfaceListener);
        routeService.removeListener(routeListener);
    }

    private void update(ResolvedRoute route) {
        synchronized (this) {
            IpPrefix prefix = route.prefix();
            EncapsulationType encap = encap();
            MultiPointToSinglePointIntent intent =
                    generateRouteIntent(prefix,
                            route.nextHop(),
                            route.nextHopMac(),
                            encap);

            if (intent == null) {
                log.debug("No interface found for route {}", route);
                return;
            }

            routeIntents.put(prefix, intent);

            List<Object> list = new ArrayList<>();
            list.add(route.nextHop());
            list.add(route.nextHopMac());
            gateInfo.put(prefix, list);

            intentSynchronizer.submit(intent);
        }
    }

    private void withdraw(ResolvedRoute route) {
        synchronized (this) {
            IpPrefix prefix = route.prefix();
            MultiPointToSinglePointIntent intent = routeIntents.remove(prefix);
            gateInfo.remove(prefix);
            if (intent == null) {
                log.trace("No intent in routeIntents to delete for prefix: {}",
                        prefix);
                return;
            }
            intentSynchronizer.withdraw(intent);
        }
    }

    /**
     * Generates a route intent for a prefix, the next hop IP address, and
     * the next hop MAC address.
     * <p/>
     * This method will find the egress interface for the intent.
     * Intent will match dst IP prefix and rewrite dst MAC address at all other
     * border switches, then forward packets according to dst MAC address.
     *
     * @param prefix            the IP prefix of the route to add
     * @param nextHopIpAddress  the IP address of the next hop
     * @param nextHopMacAddress the MAC address of the next hop
     * @param encap             the encapsulation type in use
     * @return the generated intent, or null if no intent should be submitted
     */
    private MultiPointToSinglePointIntent generateRouteIntent(
            IpPrefix prefix,
            IpAddress nextHopIpAddress,
            MacAddress nextHopMacAddress,
            EncapsulationType encap) {

        // Find the attachment point (egress interface) of the next hop
        Interface egressInterface =
                interfaceService.getMatchingInterface(nextHopIpAddress);
        if (egressInterface == null) {
            log.warn("No outgoing interface found for {}",
                    nextHopIpAddress);
            return null;
        }
        ConnectPoint egressPort = egressInterface.connectPoint();

        log.debug("Generating intent for prefix {}, next hop mac {}",
                prefix, nextHopMacAddress);

        Set<FilteredConnectPoint> ingressFilteredCPs = Sets.newHashSet();

        // TODO this should be only peering interfaces
        interfaceService.getInterfaces().forEach(intf -> {
            // Get ony ingress interfaces with IPs configured
            if (validIngressIntf(intf, egressInterface)) {
                TrafficSelector.Builder selector =
                        buildIngressTrafficSelector(intf, prefix);
                FilteredConnectPoint ingressFilteredCP =
                        new FilteredConnectPoint(intf.connectPoint(), selector.build());
                ingressFilteredCPs.add(ingressFilteredCP);
            }
        });

        // Build treatment: rewrite the destination MAC address
        TrafficTreatment.Builder treatment = DefaultTrafficTreatment.builder()
                .setEthDst(nextHopMacAddress);

        // Build the egress selector for VLAN Id
        TrafficSelector.Builder selector =
                buildTrafficSelector(egressInterface);
        FilteredConnectPoint egressFilteredCP =
                new FilteredConnectPoint(egressPort, selector.build());

        // Set priority
        int priority =
                prefix.prefixLength() * PRIORITY_MULTIPLIER + PRIORITY_OFFSET;

        // Set key
        Key key = Key.of(prefix.toString(), appId);

        MultiPointToSinglePointIntent.Builder intentBuilder =
                MultiPointToSinglePointIntent.builder()
                        .appId(appId)
                        .key(key)
                        .filteredIngressPoints(ingressFilteredCPs)
                        .filteredEgressPoint(egressFilteredCP)
                        .treatment(treatment.build())
                        .priority(priority)
                        .constraints(CONSTRAINTS);

        setEncap(intentBuilder, CONSTRAINTS, encap);

        return intentBuilder.build();
    }

    private void addInterface(Interface intf) {
        synchronized (this) {
            for (Map.Entry<IpPrefix, MultiPointToSinglePointIntent> entry : routeIntents.entrySet()) {
                // Retrieve the IP prefix and affected intent
                IpPrefix prefix = entry.getKey();
                MultiPointToSinglePointIntent intent = entry.getValue();

                // Add new ingress FilteredConnectPoint
                Set<FilteredConnectPoint> ingressFilteredCPs =
                        Sets.newHashSet(intent.filteredIngressPoints());

                // Create the new traffic selector
                TrafficSelector.Builder selector =
                        buildIngressTrafficSelector(intf, prefix);

                // Create the Filtered ConnectPoint and add it to the existing set
                FilteredConnectPoint newIngressFilteredCP =
                        new FilteredConnectPoint(intf.connectPoint(), selector.build());
                ingressFilteredCPs.add(newIngressFilteredCP);

                // Create new intent
                MultiPointToSinglePointIntent newIntent =
                        MultiPointToSinglePointIntent.builder(intent)
                                .filteredIngressPoints(ingressFilteredCPs)
                                .build();

                routeIntents.put(entry.getKey(), newIntent);
                intentSynchronizer.submit(newIntent);
            }
        }
    }

    /*
     * Handles the case in which an existing interface gets removed.
     */
    private void removeInterface(Interface intf) {
        synchronized (this) {
            for (Map.Entry<IpPrefix, MultiPointToSinglePointIntent> entry : routeIntents.entrySet()) {
                // Retrieve the IP prefix and intent possibly affected
                IpPrefix prefix = entry.getKey();
                MultiPointToSinglePointIntent intent = entry.getValue();

                // The interface removed might be an ingress interface, so the
                // selector needs to match on the interface tagging params and
                // on the prefix
                TrafficSelector.Builder ingressSelector =
                        buildIngressTrafficSelector(intf, prefix);
                FilteredConnectPoint removedIngressFilteredCP =
                        new FilteredConnectPoint(intf.connectPoint(),
                                ingressSelector.build());

                // The interface removed might be an egress interface, so the
                // selector needs to match only on the interface tagging params
                TrafficSelector.Builder selector = buildTrafficSelector(intf);
                FilteredConnectPoint removedEgressFilteredCP =
                        new FilteredConnectPoint(intf.connectPoint(), selector.build());

                if (intent.filteredEgressPoint().equals(removedEgressFilteredCP)) {
                    // The interface is an egress interface for the intent.
                    // This intent just lost its head. Remove it and let higher
                    // layer routing reroute
                    intentSynchronizer.withdraw(routeIntents.remove(entry.getKey()));
                } else {
                    if (intent.filteredIngressPoints().contains(removedIngressFilteredCP)) {
                        // The FilteredConnectPoint is an ingress
                        // FilteredConnectPoint for the intent
                        Set<FilteredConnectPoint> ingressFilteredCPs =
                                Sets.newHashSet(intent.filteredIngressPoints());

                        // Remove FilteredConnectPoint from the existing set
                        ingressFilteredCPs.remove(removedIngressFilteredCP);

                        if (!ingressFilteredCPs.isEmpty()) {
                            // There are still ingress points. Create a new
                            // intent and resubmit
                            MultiPointToSinglePointIntent newIntent =
                                    MultiPointToSinglePointIntent.builder(intent)
                                            .filteredIngressPoints(ingressFilteredCPs)
                                            .build();

                            routeIntents.put(entry.getKey(), newIntent);
                            intentSynchronizer.submit(newIntent);
                        } else {
                            // No more ingress FilteredConnectPoint. Withdraw
                            //the intent
                            intentSynchronizer.withdraw(routeIntents.remove(entry.getKey()));
                        }
                    }
                }
            }
        }
    }

    /*
     * Builds an ingress traffic selector builder given an ingress interface and
     * the IP prefix to be reached.
     */
    private TrafficSelector.Builder buildIngressTrafficSelector(Interface intf, IpPrefix prefix) {
        TrafficSelector.Builder selector = buildTrafficSelector(intf);

        // Match the destination IP prefix at the first hop
        if (prefix.isIp4()) {
            selector.matchEthType(Ethernet.TYPE_IPV4);
            // if it is default route, then we do not need match destination
            // IP address
            if (prefix.prefixLength() != 0) {
                selector.matchIPDst(prefix);
            }
        } else {
            selector.matchEthType(Ethernet.TYPE_IPV6);
            // if it is default route, then we do not need match destination
            // IP address
            if (prefix.prefixLength() != 0) {
                selector.matchIPv6Dst(prefix);
            }
        }
        return selector;
    }

    /*
     * Builds a traffic selector builder based on interface tagging settings.
     */
    private TrafficSelector.Builder buildTrafficSelector(Interface intf) {
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();

        // TODO: Consider other tag types
        // Match the VlanId if specified in the network interface configuration
        VlanId vlanId = intf.vlan();
        if (!vlanId.equals(VlanId.NONE)) {
            selector.matchVlanId(vlanId);
        }
        return selector;
    }

    // Check if the interface is an ingress interface with IPs configured
    private boolean validIngressIntf(Interface intf, Interface egressInterface) {
        if (!intf.equals(egressInterface) &&
                !intf.ipAddressesList().isEmpty() &&
                // TODO: An egress point might have two routers connected on different interfaces
                !intf.connectPoint().equals(egressInterface.connectPoint())) {
            return true;
        }
        return false;
    }

    /*
     * Triggered when the network configuration configuration is modified.
     * It checks if the encapsulation type has changed from last time, and in
     * case modifies all intents.
     */
    private void encapUpdate() {
        synchronized (this) {
            // Get the encapsulation type just set from the configuration
            EncapsulationType encap = encap();


            for (Map.Entry<IpPrefix, MultiPointToSinglePointIntent> entry : routeIntents.entrySet()) {
                // Get each intent currently registered by SDN-IP
                MultiPointToSinglePointIntent intent = entry.getValue();

                // Make sure the same constraint is not already part of the
                // intent constraints
                List<Constraint> constraints = intent.constraints();
                if (!constraints.stream()
                        .filter(c -> c instanceof EncapsulationConstraint &&
                                new EncapsulationConstraint(encap).equals(c))
                        .findAny()
                        .isPresent()) {
                    MultiPointToSinglePointIntent.Builder intentBuilder =
                            MultiPointToSinglePointIntent.builder(intent);

                    // Set the new encapsulation constraint
                    setEncap(intentBuilder, constraints, encap);

                    // Build and submit the new intent
                    MultiPointToSinglePointIntent newIntent =
                            intentBuilder.build();

                    routeIntents.put(entry.getKey(), newIntent);
                    intentSynchronizer.submit(newIntent);
                }
            }
        }
    }

    /**
     * Sets an encapsulation constraint to the intent builder given.
     *
     * @param builder     the intent builder
     * @param constraints the existing intent constraints
     * @param encap       the encapsulation type to be set
     */
    private static void setEncap(ConnectivityIntent.Builder builder,
                                 List<Constraint> constraints,
                                 EncapsulationType encap) {
        // Constraints might be an immutable list, so a new modifiable list
        // is created
        List<Constraint> newConstraints = new ArrayList<>(constraints);

        // Remove any encapsulation constraint if already in the list
        constraints.stream()
                .filter(c -> c instanceof EncapsulationConstraint)
                .forEach(c -> newConstraints.remove(c));

        // if the new encapsulation is different from NONE, a new encapsulation
        // constraint should be added to the list
        if (!encap.equals(NONE)) {
            newConstraints.add(new EncapsulationConstraint(encap));
        }

        // Submit new constraint list as immutable list
        builder.constraints(ImmutableList.copyOf(newConstraints));
    }

    private EncapsulationType encap() {
        SdnIpConfig sdnIpConfig =
                networkConfigService.getConfig(appId, SdnIpConfig.class);

        if (sdnIpConfig == null) {
            log.debug("No SDN-IP config available");
            return EncapsulationType.NONE;
        } else {
            return sdnIpConfig.encap();
        }
    }

    private boolean isInOutNet(IpAddress address) {
        for (IpPrefix prefix : gateInfo.keySet()) {
            if (prefix.contains(address))
                return true;
        }

        return false;
    }

    private MacAddress getGateMac(IpAddress address){
        for(Map.Entry<IpPrefix, List<Object>> entry : gateInfo.entrySet()){
            if (entry.getKey().contains(address))
                return (MacAddress)entry.getValue().get(1);
        }

        return MacAddress.BROADCAST;
    }

    private IpAddress getGateIp(IpAddress address){
        for(Map.Entry<IpPrefix, List<Object>> entry : gateInfo.entrySet()){
            if (entry.getKey().contains(address))
                return (IpAddress)entry.getValue().get(0);
        }

        return null;
    }

    private void flood(PacketContext context) {
        if (topologyService.isBroadcastPoint(topologyService.currentTopology(), context.inPacket().receivedFrom())) {
            // packet out
            context.treatmentBuilder().setOutput(PortNumber.FLOOD);
            context.send();
        } else {
            context.block();
        }
    }

    private void installIntent(PacketContext context, HostId srcId, HostId dstId, IpAddress srcAddress, IpAddress dstAddress, MacAddress targetMac) {
        // if the state is withdraw but still have packet in, reinstall intent
        EnumSet<IntentState> WITHDRAWN_STATES = EnumSet.of(IntentState.WITHDRAWN,
                IntentState.WITHDRAWING,
                IntentState.WITHDRAW_REQ);

        // todo: prefixLength 24
        TrafficSelector selector = DefaultTrafficSelector.builder()
                .matchEthType(Ethernet.TYPE_IPV4)
                .matchIPSrc(IpPrefix.valueOf(srcAddress, 24))
                .matchIPDst(IpPrefix.valueOf(dstAddress, 24))
                .build();
        TrafficTreatment treatment =  DefaultTrafficTreatment.builder()
                    .setEthDst(targetMac)
                    .build();

        // keep same id for the flow
        Key key;
        key = Key.of(srcAddress.toString() + dstAddress.toString(), appId);


        Host src = hostService.getHost(srcId);
        Host dst = hostService.getHost(dstId);

        ConnectPoint srcCP = src.location();
        ConnectPoint dstCP = dst.location();

        HostToHostIntent intent = (HostToHostIntent) intentService.getIntent(key);

        if (intent == null) {
            PointToPointIntent p2pIntent = PointToPointIntent.builder()
                    .appId(appId)
                    .selector(selector)
                    .treatment(treatment)
                    .filteredIngressPoint(new FilteredConnectPoint(srcCP))
                    .filteredEgressPoint(new FilteredConnectPoint(dstCP))
                    .build();

            intentService.submit(p2pIntent);
            log.info("##########################sending from install, key={}, src_host={}, dst_host={}, appId={}!!!!!!!!!!!!!!!!!", key.toString(), srcId.toString(), dstId.toString(), appId.toString());
        } else {
            IntentState intentState = intentService.getIntentState(key);
            if (WITHDRAWN_STATES.contains(intentState)) {
                HostToHostIntent hostIntent = HostToHostIntent.builder()
                        .appId(appId)
                        .selector(selector)
                        .treatment(treatment)
                        .one(srcId)
                        .two(dstId)
                        .build();
                intentService.submit(hostIntent);
            } else if (intentState == IntentState.FAILED) {
                TrafficSelector ruleSelector = DefaultTrafficSelector.builder()
                        .matchEthSrc(srcId.mac()).matchEthDst(dstId.mac()).build();

                TrafficTreatment dropTreatment = DefaultTrafficTreatment.builder()
                        .drop().build();

                ForwardingObjective objective = DefaultForwardingObjective.builder()
                        .withSelector(ruleSelector)
                        .withTreatment(dropTreatment)
                        .fromApp(appId)
                        .withPriority(intent.priority() - 1)
                        .makeTemporary(100) // hard time
                        .withFlag(ForwardingObjective.Flag.VERSATILE)
                        .add();

                flowObjectiveService.forward(context.outPacket().sendThrough(), objective);
            }
        }
    }

    private void forwardPacket(PacketContext context, Host dst) {
        TrafficTreatment treatment = DefaultTrafficTreatment.builder().setOutput(dst.location().port()).build();
        OutboundPacket packet = new DefaultOutboundPacket(dst.location().deviceId(), treatment, context.inPacket().unparsed());

        packetService.emit(packet);
        log.info("send packet: {}", packet);
    }

    private void buildArpReply(IpAddress ip, MacAddress mac, Ethernet ethPkt,ConnectPoint point){
        PortNumber dstPort= point.port();
        DeviceId deviceId = point.deviceId();

        Ethernet arpReplyPkt = ARP.buildArpReply(ip.getIp4Address(), mac, ethPkt);
        TrafficTreatment treatment = DefaultTrafficTreatment.builder().setOutput(dstPort).build();
        OutboundPacket packet = new DefaultOutboundPacket(deviceId, treatment, ByteBuffer.wrap(arpReplyPkt.serialize()));

        packetService.emit(packet);
        log.info("send arp reply: {}", packet);
    }

    private void setConnective(PacketContext context, MacAddress srcMac, MacAddress dstMac, IpAddress srcAddress, IpAddress dstAddress){
        context.treatmentBuilder().setEthDst(dstMac);

        HostId srcId = HostId.hostId(srcMac);
        HostId dstId = HostId.hostId(dstMac);

        Host dst = hostService.getHost(dstId);

        if(dst == null){
            flood(context);
            return;
        }

        installIntent(context, srcId, dstId, srcAddress, dstAddress, dstMac);
        forwardPacket(context, dst);
    }

    private class ReactivePacketProcessor implements PacketProcessor {
        @Override
        public void process(PacketContext context) {
            if (context.isHandled())
                return;
            InboundPacket pkt = context.inPacket();
            Ethernet ethPkt = pkt.parsed();

            if(ethPkt == null)
                return;

            // strategy depends on different domain(ips)
            IpAddress srcAddress;
            IpAddress dstAddress;

            MacAddress srcMac = ethPkt.getSourceMAC();
            MacAddress dstMac = ethPkt.getDestinationMAC();

            log.info("################!!!!!!!!!!!! Ethernet src: {} dst: {}", ethPkt.getSourceMAC(), ethPkt.getDestinationMAC());
            if (ethPkt.getEtherType() == Ethernet.TYPE_ARP) {
                ARP arpPkt = (ARP) ethPkt.getPayload();
                srcAddress = IpAddress.valueOf(IPv4.toIPv4Address(arpPkt.getSenderProtocolAddress()));
                dstAddress = IpAddress.valueOf(IPv4.toIPv4Address(arpPkt.getTargetProtocolAddress()));
                log.info("################!!!!!!!!!!!! ARP src: {}, {}; dst: {}, {}", IPv4.fromIPv4Address(IPv4.toIPv4Address(arpPkt.getSenderProtocolAddress())), isInOutNet(srcAddress), IPv4.fromIPv4Address(IPv4.toIPv4Address(arpPkt.getTargetProtocolAddress())), isInOutNet(dstAddress));
            }else {
                IPv4 ipPkt = (IPv4) ethPkt.getPayload();
                srcAddress = IpAddress.valueOf(ipPkt.getSourceAddress());
                dstAddress = IpAddress.valueOf(ipPkt.getDestinationAddress());
                log.info("################!!!!!!!!!!!! IPV4 src: {}, {}; dst: {}, {}", IPv4.fromIPv4Address(ipPkt.getSourceAddress()), isInOutNet(srcAddress), IPv4.fromIPv4Address(ipPkt.getDestinationAddress()), isInOutNet(dstAddress));
            }

            // Todo: same as forward in intent forward, or just active fwd
            // src == sdn && dst == sdn, intent/flood
//            if(isInOutNet(srcAddress) == false && isInOutNet(dstAddress) == false){
//                setConnective(context, srcMac, dstMac, null, null);
//            }

            // src == sdn && dst == out
            // need change dst_mac=out_host_mac to gate_mac
            // need to handle arp
            if(isInOutNet(srcAddress) == false && isInOutNet(dstAddress) == true){
                MacAddress gateMac = getGateMac(dstAddress);

                if (ethPkt.getEtherType() == Ethernet.TYPE_ARP && ethPkt.isBroadcast()) {
                    buildArpReply(dstAddress, gateMac, ethPkt, context.inPacket().receivedFrom());
                    return;
                }

                setConnective(context, srcMac, gateMac, srcAddress, dstAddress);
            }

            // src == out && dst == sdn, intent(dst_mac is the bgp speaker in sdn, this will be a problem)
            // need change the dst_mac=sdn_bgp_speaker_mac to host_mac
            if(isInOutNet(srcAddress) == true && isInOutNet(dstAddress) == false){
                Set<Host> hosts = hostService.getHostsByIp(dstAddress);
                if(hosts.isEmpty() == false && hosts.size() > 1) {
                    log.error("one ip has been shared by more the one host");
                    return;
                }
                if(hosts.isEmpty() == true) {
                    // Todo: BROADCAST also a available
//                    dstMac = MacAddress.BROADCAST;
                    log.error("no host");
                    return;
                }
                Host dst = (Host)hosts.toArray()[0];

                dstMac =dst.mac();

                setConnective(context, srcMac, dstMac, srcAddress, dstAddress);
            }

            return;
        }
    }

    private class InternalRouteListener implements RouteListener {
        @Override
        public void event(RouteEvent event) {
            switch (event.type()) {
                case ROUTE_ADDED:
                case ROUTE_UPDATED:
                    update(event.subject());
                    break;
                case ROUTE_REMOVED:
                    withdraw(event.subject());
                    break;
                default:
                    break;
            }
        }
    }

    private class InternalNetworkConfigListener implements NetworkConfigListener {
        @Override
        public void event(NetworkConfigEvent event) {
            switch (event.type()) {
                case CONFIG_REGISTERED:
                    break;
                case CONFIG_UNREGISTERED:
                    break;
                case CONFIG_ADDED:
                case CONFIG_UPDATED:
                case CONFIG_REMOVED:
                    if (event.configClass() == SdnIpConfig.class) {
                        encapUpdate();
                    }
                    break;
                default:
                    break;
            }
        }
    }

    private class InternalInterfaceListener implements InterfaceListener {
        @Override
        public void event(InterfaceEvent event) {
            switch (event.type()) {
                case INTERFACE_ADDED:
                    addInterface(event.subject());
                    break;
                case INTERFACE_UPDATED:
                    removeInterface(event.prevSubject());
                    addInterface(event.subject());
                    break;
                case INTERFACE_REMOVED:
                    removeInterface(event.subject());
                    break;
                default:
                    break;
            }
        }
    }

}
