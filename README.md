snmpgo
======

snmpgo is a golang implementation for sending SNMP messages.

Supported Message Types
-----------------------

* SNMP V1
    - GetRequest
    - GetNextRequest
* SNMP V2c
    - GetRequest
    - GetNextRequest
    - GetBulkRequest
    - V2Trap
* SNMP V3
    - GetRequest
    - GetNextRequest
    - GetBulkRequest
    - V2Trap

Examples
--------

SNMP V2c - GetRequest

```go
package main

import (
    "fmt"

    "github.com/k-sone/snmpgo"
)

func main() {
    snmp, err := snmpgo.NewSNMP(snmpgo.SNMPArguments{
        Version:   snmpgo.V2c,
        Address:   "127.0.0.1:161",
        Retries:   1,
        Community: "public",
    })
    if err != nil {
        // Failed to create snmpgo.SNMP object
        fmt.Println(err)
        return
    }

    if err = snmp.Open(); err != nil {
        // Failed to open connection
        fmt.Println(err)
        return
    }
    defer snmp.Close()

    oids, err := snmpgo.NewOids([]string{
        "1.3.6.1.2.1.1.1.0",
        "1.3.6.1.2.1.1.2.0",
        "1.3.6.1.2.1.1.3.0",
    })
    if err != nil {
        // Failed to parse Oids
        fmt.Println(err)
        return
    }

    pdu, err := snmp.GetRequest(oids)
    if err != nil {
        // Failed to request
        fmt.Println(err)
        return
    }
    if pdu.ErrorStatus() != snmpgo.NoError {
        // Received an error from the agent
        fmt.Println(pdu.ErrorStatus(), pdu.ErrorIndex())
    }

    // get VarBind list
    fmt.Println(pdu.VarBinds())

    // select a VarBind
    fmt.Println(pdu.VarBinds().MatchOid(oids[0]))
}
```

SNMP V2c - V2Trap

```go
package main

import (
    "fmt"

    "github.com/k-sone/snmpgo"
)

func main() {
    snmp, err := snmpgo.NewSNMP(snmpgo.SNMPArguments{
        Version:   snmpgo.V2c,
        Address:   "127.0.0.1:162",
        Retries:   1,
        Community: "public",
    })
    if err != nil {
        // Failed to create snmpgo.SNMP object
        fmt.Println(err)
        return
    }

    if err = snmp.Open(); err != nil {
        // Failed to open connection
        fmt.Println(err)
        return
    }
    defer snmp.Close()

    var varBinds snmpgo.VarBinds

    varBinds = append(varBinds, &snmpgo.VarBind{
        Oid:      snmpgo.OidSysUpTime,
        Variable: snmpgo.NewTimeTicks(1000),
    })
    oid, _ := snmpgo.NewOid("1.3.6.1.6.3.1.1.5.3")
    varBinds = append(varBinds, &snmpgo.VarBind{
        Oid:      snmpgo.OidSnmpTrap,
        Variable: oid,
    })
    oid, _ = snmpgo.NewOid("1.3.6.1.2.1.2.2.1.1.2")
    varBinds = append(varBinds, &snmpgo.VarBind{
        Oid:      oid,
        Variable: snmpgo.NewInteger(2),
    })
    oid, _ = snmpgo.NewOid("1.3.6.1.2.1.31.1.1.1.1.2")
    varBinds = append(varBinds, &snmpgo.VarBind{
        Oid:      oid,
        Variable: snmpgo.NewOctetString("eth0"),
    })

    if err = snmp.V2Trap(varBinds); err != nil {
        // Failed to request
        fmt.Println(err)
        return
    }
}
```

SNMP V3 - XXXX

```go
    ...
    snmp, err := snmpgo.NewSNMP(snmpgo.SNMPArguments{
        Version:       snmpgo.V3,
        Address:       "127.0.0.1:161",
        Retries:       1,
        UserName:      "MyName",
        SecurityLevel: snmpgo.AuthPriv,
        AuthPassword:  "aaaaaaaa",
        AuthProtocol:  snmpgo.Sha,
        PrivPassword:  "bbbbbbbb",
        PrivProtocol:  snmpgo.Aes,
    })
    ...
```

License
-------

MIT
