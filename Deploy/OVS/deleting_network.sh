#! /bin/bash

if exist=$(sudo ovs-vsctl br-exists ovs-internet); then sudo ovs-vsctl del-br ovs-internet; fi	
if exist=$(sudo ovs-vsctl br-exists ovs-lan1); then sudo ovs-vsctl del-br ovs-lan1; fi
if exist=$(sudo ovs-vsctl br-exists sub-lan1); then sudo ovs-vsctl del-br sub-lan1; fi
if exist=$(sudo ovs-vsctl br-exists ovs-lan2); then sudo ovs-vsctl del-br ovs-lan2; fi
if exist=$(sudo ovs-vsctl br-exists sub-lan2); then sudo ovs-vsctl del-br sub-lan2; fi
if exist=$(sudo ovs-vsctl br-exists ovs-lan3); then sudo ovs-vsctl del-br ovs-lan3; fi
if exist=$(sudo ovs-vsctl br-exists sub-lan3); then sudo ovs-vsctl del-br sub-lan3; fi
if exist=$(sudo ovs-vsctl br-exists ovs-lan4); then sudo ovs-vsctl del-br ovs-lan4; fi
if exist=$(sudo ovs-vsctl br-exists sub-lan4); then sudo ovs-vsctl del-br sub-lan4; fi
if exist=$(sudo ovs-vsctl br-exists ovs-lan5); then sudo ovs-vsctl del-br ovs-lan5; fi
if exist=$(sudo ovs-vsctl br-exists sub-lan5); then sudo ovs-vsctl del-br sub-lan5; fi

