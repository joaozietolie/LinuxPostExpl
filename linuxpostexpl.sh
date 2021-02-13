#!/bin/bash

#Lista de binarios conhecidos que podem ser explorados  (fonte: https://gtfobins.github.io/)
binarios='whois\|xargs\|nmap\|perl\|awk\|find\|bash\|sh\|man\|more\|less\|vi\|emacs\|vim\|nc\|netcat\|python\|ruby\|lua\|irb\|tar\|zip\|gdb\|pico\|scp\|git\|rvim\|script\|ash\|csh\|curl\|dash\|ed\|env\|expect\|ftp\|sftp\|node\|php\|rpm\|rpmquery\|socat\|strace\|taskset\|tclsh\|telnet\|tftp\|wget\|wish\|zsh\|ssh$\|ip$\|arp\|mtr'
LOG=linuxpostexpl"-"`date +"%d-%m-%y"`.log
#incio das funções do programa
#função de introdução
intro(){
echo -e "\e[00;32m#########################################################\e[00m\n"
echo -e "  / \ / \ / \ / \ / \   / \ / \ / \ / \   / \ / \ / \ / \ "
echo -e " ( L | I | N | U | X ) ( P | R | I | V ) ( E | N | U | M )"
echo -e "  \_/ \_/ \_/ \_/ \_/   \_/ \_/ \_/ \_/   \_/ \_/ \_/ \_/ "
echo -e "\n Ferramenta para encontrar vetores de escalação de privilégios em sistemas baseados em Linux"
echo -e "\e[00;31m Powered by: João Zietolie Ciconet(K43P) - joao@xlabs.com.br \e[00m\n"
echo -e " Exemplo de uso: ./linuxpostexpl.sh -o output\n\n"


		echo "OPÇÕES:"
		echo "-p	Palavra chave"
		echo "-s	Salva o resultado em um arquivo de sua escolha (necessita acompanhar o nome do arquivo)"
		echo "-l	Exclui o arquivo de logs criado pelo programa"
		echo "-h	Ajuda"

echo -e "\n Usuário sendo utilizado: \e[00;31m`whoami`"		
echo -e "\n Logs automaticamente salvos em linuxpostexpl-data.log após execução"

echo -e "\n\e[00;32m#########################################################\e[00m"
}

sys_info(){
	echo -e "\n\t\e[00;32m INFORMAÇÕES DE AMBIENTE \e[00m\n"

sysname=`uname -a`
echo -e "\e[00;31m[+] Informações gerais:\e[00m\n$sysname\n"

versao=`cat /etc/*release`
echo -e "\e[00;31m[+] Versão do sistema:\e[00m\n$versao\n"

up=`who -a`
echo -e "\e[00;31m[+] Uptime, runlevel, e outras infos que podem ser úteis:\e[00m\n$up"

}
user_info(){
	echo -e "\n\t\e[00;32m INFORMAÇÕES DE USUARIO E GRUPO \e[00m\n"

useri=`id`
echo -e "\e[00;31m[+] Atual user/group info:\e[00m\n$useri\n"

#Última vez que os usuários logaram
usuariosantlog=`lastlog | grep -v "*Never*" 2>/dev/null`
if [ "$usuariosantlog" ]; then
	echo -e "\e[00;31m[+] Usuários que logararam anteriormente no sistema:\e[00m\n$usuariosantlog\n" 
fi

#Quem mais esta logado
usuarioslogados=`w`
if [ "$usuarioslogados" ]; then
	echo -e "\e[00;31m[+] Usuários que também estão logados:\e[00m\n$usuarioslogados\n" 
fi

#checa hashes armazenadas no /etc/passwd
hashpasswd=`grep -v '^[^:]*:[x]' /etc/passwd`
if [ "$hashpasswd" ]; then
	echo -e "\e[00;33m[+] /etc/passwd parece conter hashes!\e[00m\n$hashpasswd\n"
fi

#conteudo do  /etc/passwd
conteudopasswd=`cat /etc/passwd`
if [ "$conteudopasswd" ]; then
	echo -e "\e[00;31m[+] Conteudo do  /etc/passwd:\e[00m\n$conteudopasswd\n"
fi

#/etc/shadow pode ser lida?
lershadow=`cat /etc/shadow 2>/dev/null`
if [ "$lershadow" ]; then
	echo -e "\e[00;33m[+] /etc/shadow pode ser lido!\e[00m\n$lershadow\n"
fi

#verifica se /etc/master.passwd pode ser lido - BSD
lermasterpasswd=`cat /etc/master.passwd 2>/dev/null`
if [ "$lermasterpasswd" ]; then
	echo -e "\e[00;33m[+] master.passwd pode ser lido!\e[00m\n$lermasterpasswd\n"
fi

#Contas root (uid 0)
sudoroot=`grep -v -E "^#" /etc/passwd | awk -F: '$3 == 0 { print $1}'`
if [ "$sudoroot" ]; then
	echo -e "\e[00;31m[+] Contas com privilégio root:\e[00m\n$sudoroot\n"
fi

echo -e "\e[00;31m[-] Visualizar se arquivos sensíveis podem ser lidos/escritos:\e[00m" ; ls -la /etc/passwd 2>/dev/null ; ls -la /etc/group 2>/dev/null ; ls -la /etc/profile 2>/dev/null; ls -la /etc/shadow 2>/dev/null ; ls -la /etc/master.passwd 2>/dev/null 
echo -e "\n" 

#Info do sudoers
sudoers=`grep -v -e '^$' /etc/sudoers 2>/dev/null | grep -v "#" 2>/dev/null`
if [ "$sudoers" ]; then
	echo -e "\e[00;31m[+] Sudoers config:\e[00m$sudoers\n"
fi

#sudo pode ser executado sem senha?
sudoperm=`echo '' 2>/dev/null | sudo -S -l -k 2>/dev/null`
if [ "$sudoperm" ]; then
	echo -e "\e[00;33m[+] Pode-se usar sudo sem uma senha!\e[00m\n$sudoperm\n"
fi


#Binarios conhecidos que podem ser executados com sudo - xargs usa apenas 1 argumento
sudobin=`echo '' | sudo -S -l -k 2>/dev/null | xargs -n 1 2>/dev/null | sed 's/,*$//g' 2>/dev/null | grep -w $binarios 2>/dev/null`
if [ "$sudobin" ]; then
	echo -e "\e[00;33m[+] Binarios passiveis de exploração com sudo:\e[00m\n$sudobin\n"
fi

#checa se a home do root esta acessivel
roothomedir=`ls -ahl /root/ 2>/dev/null`
if [ "$roothomedir" ]; then
	echo -e "\e[00;33m[+] Podemos acessar o home do root!\e[00m\n$roothomedir\n"
fi

#Permissões do diretório home -
homedirperms=`ls -ahl /home/ 2>/dev/null`
if [ "$homedirperms" ]; then
	echo -e "\e[00;31m[+] Permissões do diretório home:\e[00m\n$homedirperms\n"
fi

#Procura por arquivos que podemos escrever mas não pertence ao usuário atual 
arquivosescrita1=`find / -writable ! -user \`whoami\` -type f ! -path "/proc/*" ! -path "/sys/*" -exec ls -al {} \; 2>/dev/null`
if [ "$arquivosescrita1" ]; then
	echo -e "\e[00;31m[+] Arquivos que podem ser escritos e não pertencem ao seu usuário:\e[00m\n$arquivosescrita1\n"
fi


#Procura por arquivos ocultos 
hiddenfiles=`find / -name ".*" -type f ! -path "/proc/*" ! -path "/sys/*" -exec ls -alh {} \; 2>/dev/null`
if [ "$hiddenfiles" ]; then
	echo -e "\e[00;31m[+] Arquivos Ocultos:\e[00m\n$hiddenfiles\n"
fi

#checa se o root pode logar via ssh
sshrootlogin=`grep "PermitRootLogin " /etc/ssh/sshd_config 2>/dev/null | grep -v "#"`
if [ "$sshrootlogin" = "yes" ]; then
	echo -e "\e[00;31m[+] Root pode logar via SSH:\e[00m" ; grep "PermitRootLogin " /etc/ssh/sshd_config 2>/dev/null | grep -v "#"\n
fi

}

env_info()
{
        echo -e "\n\t\e[00;32m INFORMAÇÕES DO AMBIENTE \e[00m\n"
 

#Info de variáveis do ambiente
envinfo=`env 2>/dev/null | grep -v 'LS_COLORS' 2>/dev/null`
if [ "$envinfo" ]; then
	echo -e "\e[00;31m[+] Informações de variáveis de ambiente:\e[00m\n$envinfo"\n
fi

#checa se o SELInux esta habilitado(Mecanismo de segurança MAC no kernel)
sestatus=`sestatus 2>/dev/null`
if [ "$sestatus" ]; then
	echo -e "\e[00;31m[+] SELinux esta presente no sistema:\e[00m\n$sestatus\n"
fi

#Configuração da variável $PATH(VARIAVEL QUE ARMAZENA LOCALIZAÇÕES DE EXECUTÁVEIS)
pathinfo=`echo $PATH 2>/dev/null`
if [ "$pathinfo" ]; then
	echo -e "\e[00;31m[+] Variável PATH:\e[00m\n$pathinfo\n" 
fi

#Shells disponiveis
shellinfo=`cat /etc/shells 2>/dev/null`
if [ "$shellinfo" ]; then
	echo -e "\n\e[00;31m[+] Shells Disponíveis:\e[00m\n$shellinfo\n"
fi

#Politica de senha presente no arquivo: /etc/login.defs
logindefs=`grep "^PASS_MAX_DAYS\| ^PASS_MIN_DAYS\|^PASS_WARN_AGE\|^ENCRYPT_METHOD" /etc/login.defs 2>/dev/null`
if [ "$logindefs" ]; then
	echo -e "\e[00;31m[+] Informações de política de senhas:\e[00m\n$logindefs\n"
fi

}


job_info()
{
        echo -e "\n\t\e[00;32m INFORMAÇÕES DE TAREFAS DO SISTEMA \e[00m\n"


#verifica se tem algum cron job configurado
cronjobs=`ls -la /etc/cron* 2>/dev/null`
if [ "$cronjobs" ]; then
	echo -e "\e[00;31m[+] Tarefas da Cron:\e[00m\n$cronjobs\n"
fi

#verifica se podemos manipular esse cron job
cronjobperms=`find /etc/cron* -perm -0002 -type f -exec ls -la {} \; -exec cat {} 2>/dev/null \;`
if [ "$cronjobperms" ]; then
	echo -e "\e[00;33m[+] Podemos manipular estes cron jobs:\e[00m\n$cronjobperms\n"
fi

#crontab conteudo
crontabcont=`cat /etc/crontab 2>/dev/null`
if [ "$crontabcont" ]; then
	echo -e "\e[00;31m[+] Crontab conteudo:\e[00m\n$crontabcont\n"
fi

}
software_configs()
{
        echo -e "\n\t\e[00;32m INFORMAÇÕES DE SOFTWARES \e[00m\n"


#Versao do sudo
sudover=`sudo -V 2>/dev/null| grep "Sudo version" 2>/dev/null`
if [ "$sudover" ]; then
	echo -e "\e[00;31m[+] VersÃo do sudo: (Cheque se possui alguma vulnerabilidade conhecida))\e[00m\n$sudover\n" 
fi

#mysql detalhes - se instalado
mysqlver=`mysql --version 2>/dev/null`
if [ "$mysqlver" ]; then
	echo -e "\e[00;31m[+] Versão MYSQL:\e[00m\n$mysqlver\n"
fi

#TENTA LOGAR NO MYSQL COM LOGIN E SENHA ROOT
mysqlconnect=`mysqladmin -u root -p root version 2>/dev/null`
if [ "$mysqlconnect" ]; then
	echo -e "\e[00;33m[+] Podemos conectar no mysql com login e senha root!\e[00m\n$mysqlconnect\n"
fi

#mysql detalhes de versão e login sem senha
mysqlconnectnopass=`mysqladmin -u root version 2>/dev/null`
if [ "$mysqlconnectnopass" ]; then
	echo -e "\e[00;33m[+] Podemos conectar no mysql com usuário root e sem senha!\e[00m\n$mysqlconnectnopass\n"
fi

#apache detalhes
apachever=`apache2 -v 2>/dev/null; httpd -v 2>/dev/null`
if [ "$apachever" ]; then
	echo -e "\e[00;31m[+] Versão Apache:\e[00m\n$apachever\n"
fi

#Em qual conta o apache está sendo executado
apacheuser=`grep -i 'user\|group' /etc/apache2/envvars 2>/dev/null |awk '{sub(/.*\export /,"")}1' 2>/dev/null`
if [ "$apacheuser" ]; then
	echo -e "\e[00;31m[+] Apache está sendo executado com o usuário:\e[00m\n$apacheuser\n"
fi

#checa o htpasswd(arquivo de senhas do apache)
htpasswd=`find / -name .htpasswd -print -exec cat {} \; 2>/dev/null`
if [ "$htpasswd" ]; then
	echo -e "\e[00;33m[-] htpasswd foi encontrado e pode conter senhas:\e[00m\n$htpasswd\n"
fi

}

misc()
{
        echo -e "\n\t\e[00;32m CHECAGENS ADICIONAIS \e[00m\n"


#checa se aplicações conhecidas para privesc estão disponíveis
echo -e "\e[00;31m[-] Localização de executáveis que podem ser úteis para privesc:\e[00m" ; which nc 2>/dev/null ; which netcat 2>/dev/null ; which wget 2>/dev/null ; which nmap 2>/dev/null ; which gcc 2>/dev/null; which curl 2>/dev/null \n

#lista arquivos suid que podem ser interessantes que estão na lsita de binarios
intsuid=`find / -perm -4000 -type f -exec ls -la {} \; 2>/dev/null | grep -w $binarios 2>/dev/null`
if [ "$intsuid" ]; then
	echo -e "\e[00;33m[+] Arquivos SUID que podem ser interessantes:\e[00m\n$intsuid\n"
fi

#Arquivos SUID gravaveis
wsuid=`find / -perm -4007 -type f -exec ls -la {} 2>/dev/null \;`
if [ "$wsuid" ]; then
	echo -e "\e[00;33m[+] Arquivos SUID que podem ser editados:\e[00m\n$wsuid\n"
fi

#Arquivos SUID gravaveis do root
wsuidrt=`find / -uid 0 -perm -4007 -type f -exec ls -la {} 2>/dev/null \;`
if [ "$wsuidrt" ]; then
	echo -e "\e[00;33m[+] Arquivos SUID gravaveis do root:\e[00m\n$wsuidrt\n"
fi

#Procura por arquivos SGID
findsgid=`find / -perm -2000 -type f -exec ls -la {} 2>/dev/null \;`
if [ "$findsgid" ]; then
  echo -e "\n\e[00;31m[+] Arquivos SGID:\e[00m\n$findsgid\n"
fi

#lista arquivos SGID interessantes que estão na lista de binarios
intsgid=`find / -perm -2000 -type f  -exec ls -la {} \; 2>/dev/null | grep -w $binarios 2>/dev/null`
if [ "$intsgid" ]; then
  echo -e "\e[00;33m[+] Arquivos SGID que podem ser interessantes:\e[00m\n$intsgid\n"
fi

#lista arquivos SGID gravaveis
wsgid=`find / -perm -2007 -type f -exec ls -la {} 2>/dev/null \;`
if [ "$wsgid" ]; then
  echo -e "\e[00;33m[+] Arquivos SGID gravaveis:\e[00m\n$wsgid\n"
fi

#Arquivos SGID gravaveis do root
wsgidrt=`find / -uid 0 -perm -2007 -type f -exec ls -la {} 2>/dev/null \;`
if [ "$wsgidrt" ]; then
  echo -e "\e[00;33m[+] Arquivos SGID gravaveis do root:\e[00m\n$wsgidrt\n"
fi

#Procura por arquivos com credenciais do git
gitcred=`find / -name ".git-credentials" 2>/dev/null`
if [ "$gitcred" ]; then
  	echo -e "\e[00;33m[+] Credenciais git salvas!:\e[00m\n$gitcred\n"
fi

#Pesquisa por arquivos .plan na pasta home, pode conter informações úteis
usrplan=`find /home -iname *.plan -exec ls -la {} \; -exec cat {} 2>/dev/null \;`
if [ "$usrplan" ]; then
	echo -e "\e[00;31m[+] Arquivos .plan conteúdo e permissões:\e[00m\n$usrplan\n"
fi

#Pesquisa por arquivos .bkp
bkp=`find / -iname *.bkp -exec ls -la {}  2>/dev/null \;`
if [ "$bkp" ]; then
        echo -e "\e[00;31m[+] Arquivos .bkp:\e[00m\n$bkp\n"
fi

#algum rhost disponível? - pode permitir logar em outro user
rhostsusr=`find /home -iname *.rhosts -exec ls -la {} 2>/dev/null \; -exec cat {} 2>/dev/null \;`
if [ "$rhostsusr" ]; then
	echo -e "\e[00;33m[+] rhost e conteúdo:\e[00m\n$rhostsusr\n"
fi

#Verifica arquivos de usuários 
usrhist=`ls -la ~/.*_history 2>/dev/null`
if [ "$usrhist" ]; then
	echo -e "\e[00;31m[+] Arquivos de histórico acessíveis:\e[00m\n$usrhist\n"
fi

#Verifica se esta acessível historico do root
roothist=`ls -lha /root/.*_history 2>/dev/null`
if [ "$roothist" ]; then
	echo -e "\e[00;33m[+] HIstórico do root acessível! Pode conter senhas!!!\e[00m\n$roothist\n"
fi

#Verifica emails
email=`ls -lha /var/mail 2>/dev/null`
if [ "$email" ]; then
	echo -e "\e[00;31m[+] Conteúdo de e-mails em /var/mail:\e[00m\n$email\n"
fi

#Verifica emails root
emailroot=`head /var/mail/root 2>/dev/null`
if [ "$emailroot" ]; then
	echo -e "\e[00;33m[+] Conteúdo de e-mails do root em /var/mail/root:\e[00m\n$emailroot\n" 
fi
}

clean(){
if [ -e "$LOG" ]; then
  `rm -f $LOG`
  echo -e "\e[00;33m[+] Arquivo de logs  deletado com sucesso!)\e[00m\n" 
  echo -e "\n"
  	else
	echo -e "\e[00;33m[-] Arquivo de logs inexistente ou não encontrado!)\e[00m\n"

fi
}

calleach(){

	
	intro
	sys_info
	user_info
	env_info
	job_info
	misc
	
}

while getopts "p:s:lh" parametro; do
 case "${parametro}" in
    p) palavrachave=${OPTARG};;
    s) saida=${OPTARG};;
    l) clean; exit;;
    h) intro; exit;;
 esac
done


#Chama todas as funções e se usado a opção "-s" joga o conteudo para um arquivo, se não ira apenas jogar para o arquivo de LOG
calleach | tee -a $saida $LOG 2>/dev/null
