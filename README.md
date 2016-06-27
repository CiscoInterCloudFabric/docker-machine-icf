# docker-machine-icf
Cisco ICF Docker Machine plugin

# Build

cd bin
make

# RUN

## Parameters

1. --icf-server [$ICF_SERVER]
   IP address of Cisco Intercloud For Business
2. --icf-username [$ICF_USERNAME]
   Tenant User name on Cisco Intercloud For Business
3. --icf-password [$ICF_PASSWORD]
   Tenant User password on Cisco Intercloud For Business
4. --icf-server-cert [$ICF_SERVER_CERT]
   HTTPS Server Certificate of Cisco Intercloud For Business
5. --icf-vdc [$ICF_VDC]
   UUID of VDC assigned to the tenant
6. --icf-catalog [$ICF_CATALOG]
   UUID of Catalog (VM Template) published for the tenant
7. --icf-network [$ICF_NETWORK]
   UUID of Network published for the tenant
8. --icf-provider-access [$ICF_PROVIDER_ACCESS]
   Does the VM require Provider Access (Native service access)
9. --icf-ssh-user [$ICF_SSH_USER]
   Linux User name of the VM (based on Catalog)
10. --icf-ssh-password [$ICF_SSH_PASSWORD]
   Linux User password of the VM (based on Catalog)

