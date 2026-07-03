# LDAP stuff

A collection of LDAP stuff for managing users and groups where ID information
is stored in an LDAP server.

## Initializing the package

It is convenient to initialize the package with variables that can be used
by functions within it to manage the connection to LDAP.  In particular,
there are variables and package-level functions to create a connection for
a read-only identity and for an entity that can modify LDAP entries.

## Using the package

There is an `acctmgmt-examples` script (draft only) to illustrate the functions
included in the `acctmgmt` package.
