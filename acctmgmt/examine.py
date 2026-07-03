from acctmgmt import be_an_admin, be_a_reader
from ldap3 import Server, Connection, ObjectDef, AttrDef, Reader

debug = True

# Convert plain string to the LDAP query parameter
group = 'cn: ' + 'vaccmaestro'
conn = be_a_reader()

# Define the group object being queried and set the search base
group_def = ObjectDef('posixGroup', conn)
search_base = 'dc=uvm,dc=edu'

# Define the reader and the query it will perform
reader = Reader(conn, group_def, search_base)
reader.query = group

# res will be a list of ldap3.abstract.entry.Entry objects, and for an
# exact match, should contain only one entry.
res = reader.search()

# Make an
if len(res) == 1:
    entry = res[0]
else:
    print("res had more than one entry")

# print some information if debug is set
if debug is True:
    print(f"entry is a {type(entry)}")
    print(f"The group found was {entry.entry_dn}")
    print("  and it has the following useful attributes:")
    print("Useful UVM attributes are:")
    for attr in ['cn', 'gidNumber', 'memberUid']:
        print(f"    entry attribute {attr} is {entry[attr]}")
conn.unbind()
