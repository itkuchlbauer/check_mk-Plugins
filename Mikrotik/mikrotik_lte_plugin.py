#!/usr/bin/env python3

from .agent_based_api.v1 import *
import time


def discover_mikrotik_lte(section):
    ltesection = section[0]
    ifsection = section[1]
    for index, _rssi, _rsrq, _rsrp, _sinr, _acctec in ltesection:
        for ifindex, name, _adminstate, _operstate, _bytesin, _bytesout in ifsection:
            if(index==ifindex):
                yield Service(item = name)

def check_mikrotik_lte(item, params, section):
    ltesection = section[0]
    ifsection = section[1]
    for index, name, adminstate, operstate, bytesin, bytesout in ifsection:
        if(item==name):
            searchindex = index
            if(adminstate == "2"):
                stateval = State.OK
                summaryval = "State: Disabled"
            elif(adminstate == "1" and operstate == "1"):
                stateval = State.OK
                summaryval = "State: Up"
            elif(adminstate == "1" and operstate == "2"):
                stateval = State.CRIT
                summaryval = "State: Down"
            else:
                stateval = State.UNKNOWN
                summaryval = "State: Unknown"
            yield Result(state = stateval, summary = summaryval)
            nowtime = time.time()
            valuestore = get_value_store()
            ratein = get_rate(valuestore, f"if.{index}.bytesin", nowtime, int(bytesin))
            yield Metric("if_in_bps", ratein)
            rateout = get_rate(valuestore, f"if.{index}.bytesout", nowtime, int(bytesout))
            yield Metric("if_out_bps", rateout)
    for index, rssi, rsrq, rsrp, sinr, acctec in ltesection:
        if(index==searchindex):
            yield Metric("RSSI", int(rssi))
            yield Metric("RSRQ", int(rsrq))
            yield Metric("RSRP", int(rsrp))
            yield Metric("SINR", int(sinr))
            yield Result(state = State.OK, summary = f"Access Technology: {acctec}")

register.snmp_section(
    name = "mikrotik_lte",
    detect = startswith(".1.3.6.1.2.1.1.1.0", "RouterOS"),
    fetch = [
        SNMPTree(
            base = ".1.3.6.1.4.1.14988.1.1.16.1.1",
            oids = [
                OIDEnd(),
                "2",
                "3",
                "4",
                "7",
                "14",
            ],
        ),
        SNMPTree(
            base = ".1.3.6.1.2.1.2.2.1",
            oids = [
                OIDEnd(),
		"2",
                "7",
                "8",
                "10",
                "16",
            ],
        ),
    ]
)

register.check_plugin(
    name="mikrotik_lte_plugin",
    sections = ["mikrotik_lte",],
    service_name="LTE Modem %s",
    discovery_function=discover_mikrotik_lte,
    check_function=check_mikrotik_lte,
    check_default_parameters={},
)
