# -- functions for managing VACC user groups

from acctmgmt import (
    be_an_admin, be_a_reader, MIN_GID_NUMBER, MAX_GID_NUMBER,
    LDAP_BASE, GROUPS_BASE, PEOPLE_BASE
    )
from ldap3 import (
    Server, Connection, ObjectDef, AttrDef, Reader,
    MODIFY_ADD, MODIFY_DELETE, MODIFY_REPLACE,
    )

def examine(group, debug=False):
    conn = be_a_reader()
    group_def = ObjectDef('posixGroup', conn)
    reader = Reader(conn, group_def, GROUPS_BASE, query=f"cn: {group}")
    res = reader.search()
    if len(res) != 1:
        raise ValueError(
            f"Expected exactly one group matching '{group}', found {len(res)}"
        )
    else:
        entry = res[0]
    if debug is True:
        print(f"entry has the description: {entry.description}")
        print(f"entry is a {type(entry)}")
        print(f"The group found was {entry.entry_dn}")
        print("  and it has the following attributes:")
        for attr in entry.entry_attributes:
            print(f"    {attr}")
    print("Useful UVM attributes and their values are:")
    for attr in ['cn', 'gidNumber', 'memberUid', 'description']:
        print(f"    entry attribute {attr} is {entry[attr]}")
    conn.unbind()
    return entry

def _find_group_dn(group):
    """Look up a posixGroup's DN using the read-only identity."""
    conn = be_a_reader()
    try:
        group_def = ObjectDef('posixGroup', conn)
        search_base = 'dc=uvm,dc=edu'
        reader = Reader(conn, group_def, search_base)
        reader.query = 'cn: ' + group
        res = reader.search()
        if len(res) != 1:
            raise ValueError(
                f"Expected exactly one group matching '{group}', found {len(res)}"
            )
        return res[0].entry_dn
    finally:
        conn.unbind()

def add_user_to_group(group, user, debug=False):
    """Add `user` to the memberUid attribute of `group`."""
    dn = _find_group_dn(group)
    conn = be_an_admin()
    try:
        success = conn.modify(dn, {'memberUid': [(MODIFY_ADD, [user])]})
        if debug:
            print(f"add_user_to_group: dn={dn}, user={user}, success={success}")
            print(conn.result)
        return success
    finally:
        conn.unbind()

def remove_user_from_group(group, user, debug=False):
    """Remove `user` from the memberUid attribute of `group`."""
    dn = _find_group_dn(group)
    conn = be_an_admin()
    try:
        success = conn.modify(dn, {'memberUid': [(MODIFY_DELETE, [user])]})
        if debug:
            print(f"remove_user_from_group: dn={dn}, user={user}, success={success}")
            print(conn.result)
        return success
    finally:
        conn.unbind()

def set_group_description(group, description, debug=False):
    """Set (or replace) the description attribute of `group`."""
    dn = _find_group_dn(group)
    conn = be_an_admin()
    try:
        success = conn.modify(dn, {'description': [(MODIFY_REPLACE, [description])]})
        if debug:
            print(f"set_group_description: dn={dn}, description={description!r}, success={success}")
            print(conn.result)
        return success
    finally:
        conn.unbind()


def _next_gid_number(conn, search_base=GROUPS_BASE,
                      min_gid=MIN_GID_NUMBER, max_gid=MAX_GID_NUMBER):
    """Find the lowest unused gidNumber in [min_gid, max_gid]."""
    entries = conn.extend.standard.paged_search(
        search_base=search_base,
        search_filter=f'(&(objectClass=posixGroup)(gidNumber>={min_gid}))',
        attributes=['gidNumber'],
        paged_size=500,
        generator=True,
    )
    used = set()
    for entry in entries:
        try:
            gid = int(entry['attributes']['gidNumber'][0])
        except (KeyError, IndexError, ValueError, TypeError):
            continue
        if min_gid <= gid <= max_gid:
            used.add(gid)
    for candidate in range(min_gid, max_gid + 1):
        if candidate not in used:
            return candidate
    raise RuntimeError(f"No free gidNumber available in range {min_gid}-{max_gid}")


def create_group(group, members=None, description="Useful group", debug=False):
    """Create a new posixGroup entry, allocating the next free gidNumber
    automatically from [MIN_GID_NUMBER, MAX_GID_NUMBER].

    group        - the cn (group name) for the new group
    members      - optional list of memberUid strings to seed the group with
    description  - defaults to "Useful group"
    """
    conn_r = be_a_reader()
    try:
        gid_number = _next_gid_number(conn_r)
    finally:
        conn_r.unbind()
    dn = f"cn={group},{GROUPS_BASE}"
    attributes = {
        'objectClass': ['posixGroup', 'top'],  # confirm actual values match your schema
        'cn': group,
        'gidNumber': gid_number,
        'description': description,
    }
    if members:
        attributes['memberUid'] = members
    conn = be_an_admin()
    try:
        success = conn.add(dn, attributes=attributes)
        if debug:
            print(f"create_group: dn={dn}, gid_number={gid_number}, success={success}")
            print(conn.result)
        return success
    finally:
        conn.unbind()


def empty_group(group, debug=False):
    """Remove all members from a group's memberUid attribute."""
    dn = _find_group_dn(group)
    conn = be_an_admin()
    try:
        success = conn.modify(dn, {'memberUid': [(MODIFY_REPLACE, [])]})
        if debug:
            print(f"empty_group: dn={dn}, success={success}")
            print(conn.result)
        return success
    finally:
        conn.unbind()


def delete_group(group, force=False, debug=False):
    dn = _find_group_dn(group)
    conn = be_a_reader()
    try:
        conn.search(dn, '(objectClass=posixGroup)', attributes=['memberUid'])
        members = conn.entries[0].memberUid.values if conn.entries else []
    finally:
        conn.unbind()
    if members and not force:
        raise ValueError(
            f"Group '{group}' has {len(members)} member(s); "
            f"pass force=True to delete anyway"
        )
    conn = be_an_admin()
    try:
        success = conn.delete(dn)
        if debug:
            print(f"delete_group: dn={dn}, success={success}")
            print(conn.result)
        return success
    finally:
        conn.unbind()
