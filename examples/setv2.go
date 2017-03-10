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
		Community: "private",
	})
	if err != nil {
		// Failed to create snmpgo.SNMP object
		fmt.Println(err)
		return
	}

	// Build VarBind list
	var varBinds snmpgo.VarBinds

	// SNMPv2-MIB::sysName
	oid, _ := snmpgo.NewOid("1.3.6.1.2.1.1.5.0")
	varBinds = append(varBinds, snmpgo.NewVarBind(oid, snmpgo.NewOctetString([]byte("myhost.example.com"))))

	// SNMPv2-MIB::snmpEnableAuthenTraps - enabled(1), disabled(2)
	oid, _ = snmpgo.NewOid("1.3.6.1.2.1.11.30.0")
	varBinds = append(varBinds, snmpgo.NewVarBind(oid, snmpgo.NewInteger(2)))

	if err = snmp.Open(); err != nil {
		// Failed to open connection
		fmt.Println(err)
		return
	}
	defer snmp.Close()

	pdu, err := snmp.SetRequest(varBinds)
	if err != nil {
		// Failed to request
		fmt.Println(err)
		return
	}
	if pdu.ErrorStatus() != snmpgo.NoError {
		// Received an error from the agent
		fmt.Println(pdu.ErrorStatus(), pdu.ErrorIndex())
		return
	}

	// Done
	for _, val := range pdu.VarBinds() {
		fmt.Printf("%s = %s: %s\n", val.Oid, val.Variable.Type(), val.Variable)
	}
}
