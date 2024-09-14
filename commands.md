* Run Playbook: ansible-playbook -i inventory.ini playbook.yml 
* Run Playbook in verbose mode: ansible-playbook -i inventory.ini playbook.yml -v
* Check Playbook [ansible will not run commands in real just show what it will do once run]: 
ansible-playbook -i inventory.ini playbook.yml  --check
* Run plabook in diff mode to see what all will change:
ansible-playbook -i inventory.ini playbook.yml  --check --diff
* Check playbook Syntax:
ansible-playbook -i inventory.ini playbook.yml  --syntax-check
* Check Style related issues in playbook:
ansible-lint playbook.yml

# Roles

## Create Role
* ansible-galaxy init <role-name>
* A folder will be created with some default files

## Search Role online from ansible-galaxy
* ansible-galaxy search <role-name>

## Install Role
* ansible-galaxy install <role-name> -p <directory>

## List currently installed roles
* ansible-galaxy list


