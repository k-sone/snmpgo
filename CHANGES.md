## 2.0.1 (2016/05/26)

- Raise an error when unmarshalling an invalid SNMP version

## 2.0.0 (2016/02/11)

- Support for receiving of trap events (V2c only) [#4](https://github.com/k-sone/snmpgo/pull/4)

#### Breaking Changes

- Change to return a pointer of xxError struct [#1](https://github.com/k-sone/snmpgo/pull/1)
- Rename `ResponseError` to `MessageError`

## 1.0.1 (2015/07/12)

- Fix validating authoritative engine

## 1.0.0 (2015/01/24)

- Initial release
