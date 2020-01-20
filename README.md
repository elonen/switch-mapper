# switch-mapper

Recursive Ethernet switch mapper using SNMP/LLDP.
Also resolves IPv4 addresses and hostnames (no IPv6 support currently).
Outputs JSON.

## Installing

Download a [binary release](https://github.com/elonen/switch-mapper/releases) or install
with pip:

```
python3.8 -m venv venv
source venv/bin/activate    # Windows: CALL venv\Scripts\activate
pip install --editable git://github.com/elonen/switch-mapper.git#egg=switch-mapper
```

...or if you wish to develop:

```
git clone git+ssh://git@github.com/elonen/switch-mapper.git
cd switch-mapper
./init-env.sh    # on Windows requires Mingw (Git Bash) or Cygwin
```

Either way, you can now type `switch-mapper` on the command line.
