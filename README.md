![Imgur](https://imgur.com/BrD0riF.jpg)

# Trabalho Final de Segurança da Informação:

### Universidade do Sul de Santa Catarina
### Nome: Murilo Furlan de Sousa
### Segurança de Redes
### Data: 01/12/2021

### Neste arquivo será documentado o processo completo de um pentest na minha rede interna e externa, desde reconhecimento inicial até exploração de vulnerabilidades encontradas.
#
## Etapas:
 - Reconhecimento da rede externa com approach black box, sem informações anteriores sobre os alvos ou funcionamento interno da rede e sistemas;
 - Invasão da Rede Wireless com Wifite e Hashcat
 - Descoberta e Footprint de hosts dentro da rede interna com arp-scan e nmap
 - Enumeração de serviços e vulnerabilidades usando nmap e nse scripts
 - Identificação de Vulnerabilidades com Searchsploit (Exploit-DB)
 - Confirmação e exploração dessas vulnerabilidades com Metasploit

#
## Invasão da rede Wireless:
### Antes de tudo, precisamos do acesso à rede interna do alvo, para isso vamos precisar pegar o 3-way-handshake do protocolo WPA-2 com a ferramenta Wifite e depois crackeá-lo com o Hashcat;
   - Listagem das redes com a ferramenta *airmon-ng* e *airodump-ng*
      - Usagem *aircrack-ng* suite:
        - sudo airmon-ng nome_interface start -> Coloca a interface nome_interface no Monitor mode.
        - airodump-ng nome_interface -> Mostra no console as redes wireless  identificadas nas proximidades.
        - sudo airmon-ng nome_interface stop -> Retorna a interface para modo managed (padrão)

| *Usando airodump-ng para identificar redes wireless* |
|:--:| 
| ![Imgur](https://imgur.com/YcW8c5o.jpg) |

   - Captura do Handshake usando o programa wifite, script em python que auxilia no pentesting de redes wireless.
      - https://github.com/derv82/wifite2
      - Utilização: python3 ./wifite.py

| *Usando o Wifite e selecionando nosso alvo* |
|:--:| 
| ![Imgur](https://imgur.com/kbSknzK.jpg) |

| *Handshake capturado com sucesso!* |
|:--:| 
| ![Imgur](https://imgur.com/k9ExEIt.jpg) |

 - Conversão do handshake.pcap para .hccapx, formato que a ferramenta hashcat utiliza.
    - https://hashcat.net/cap2hashcat/

 - Brute forcing do handshake obtido pelo wifite usando a ferramenta Hashcat
    - https://hashcat.net/hashcat/
    - Usagem hashcat:
        - **hashcat -a 0 -m 2500 ./handshake.hccapx ./probable-v2-top12000.txt**
        - **-a 0** -> Modo de ataque brute force, podendo ou não usar uma wordlist
        - **-m 2500** -> Especifica o tipo de hash, no caso é WPA2 (handshake capturado)
        - **./handshake.hccapx** -> Caminho para o arquivo com os hashes
        - **./probable-v2-top12000.txt** -> Caminho para o arquivo com as possíveis senhas (**wordlist**)

| *Senha crackeada com sucesso!* |
|:--:| 
| ![Imgur](https://imgur.com/08YCegj.jpg) |
#
## Descoberta de Hosts e Footprint
 - Já dentro da rede interna, precisamos mapear os hosts e encontrar o nosso alvo, uma máquina rodando o sistema Metasploitable, intencionamente vulnerável para que estudantes e profissionais da área de segurança treinem e apliquem seus conhecimentos.
 - Usagem nmap:
     - Para descoberta e enumeração preliminar de hosts: **sudo nmap -sS -O -oX 192.168.3.1/24 -vv**
     - Para enumeração completa do nosso alvo Metasploitable: **sudo nmap -sS -sV --script vuln -O -oX ./scan_alvo.xml 192.168.3.80 -vv**
     - **-sS** -> Especifica o tipo de scan, nesse caso o scan de SYN, que não completa o 3-way-handshake e é mais rápido
     - **-sV** -> Flag para enumerar serviços rodando nos alvos e suas versões.
     - **--script vuln** -> Habilita o uso de scripts adicionais de detecção de vulnerabilidades
     - **-O** -> Especifica para que o nmap use scripts de detecção de sistemas operacionais
     - **-oX** -> Especifica o formato de saída XML, que será usado com a ferramenta Searchsploit, do Exploit-DB
     - **./scan_alvo.xml** -> Caminho para o arquivo de saída
     - **-vv** -> Aumenta a verbosidade do output, trazendo informações adicionais encontradas

| *Usando a ferramenta arp-scan para descoberta inicial e rápida de hosts* |
|:--:| 
| ![Imgur](https://imgur.com/eByzN9F.jpg) |

| *Enumeração e descoberta de hosts na subrede 192.168.3.0/24 com nmap* |
|:--:| 
| ![Imgur](https://imgur.com/OIwqziO.jpg) |

| *Usando scripts nse do nmap para descoberta de vulnerabilidades no alvo 192.168.3.80 (metasploitable)* |
|:--:| 
| ![Imgur](https://imgur.com/cph3dzt.jpg) |

 - Só com o output dos scripts do nmap já temos uma enorme lista de possíveis vulnerabilidades encontradas, que serão confirmadas posteriormente
 - Dentre essas vulnerabilidades encontradas, temos até algumas de execução remota de código *(RCE)* com *CVSS 10* e exploits publicos funcionais

#
## Identificação de vulnerabilidades com a ferramenta Searchsploit
 - Aqui usei a ferramenta Searchsploit do Exploit-DB para ler o arquivo .xml de output do scan completo do nmap, onde a ferramenta vai relacionar os serviços encontrados e suas versões com vulnerabilidades já conhecidas.
 - Usagem: ./searchsploit --nmap ./scan_alvo.xml

| *Usando a ferramenta Searchsploit e nmap para confirmar a presença do serviço vulnerável na máquina* |
|:--:| 
| ![Imgur](https://imgur.com/JubDHxP.jpg) |

#
## Vulnerabilidades encontradas
- Foram encontradas dezenas de vulnerabilidades, entre elas vou listar algumas vulnerabilidades divididas por categoria:
### **Execução Arbitrária de Código (RCE):**
 - UnrealIRCD 3.2.8.1 Backdoor Command Execution
   - Esta vulnerabilidade é um backdoor que foi implementado na versão 3.2.8.1 do UnrealIRC e executa comandos arbitrários enviados por atacantes no alvo
   - Módulo do Metasploit usado: exploit/unix/irc/unreal_ircd_3281_backdoor
   - Referência: https://github.com/rapid7/metasploit-framework/blob/master//modules/exploits/unix/irc/unreal_ircd_3281_backdoor.rb

 - VSFTPD v2.3.4 Backdoor Command Execution
   - Esta vulnerabilidade é também um backdoor implementado em uma versão específica do servidor de FTP VSFTPD 2.3.4
   - Módulo do Metasploit usado: exploit/unix/ftp/vsftpd_234_backdoor
   - Referência: https://www.rapid7.com/db/modules/exploit/unix/ftp/vsftpd_234_backdoor/

| *Pesquisando e selecionando o módulo /exploits/unix/irc/unreal_ircd_3281_backdoor no Metasploit* |
|:--:| 
| ![Imgur](https://imgur.com/BtGHq4i.jpg) |

| *Configurando parâmetros e executando o exploit, resultando em um shell de root no alvo!* |
|:--:| 
| ![Imgur](https://imgur.com/h7Ha0zF.jpg) |

#
### **Ataques de Negação de Serviço:**
 - Slow Loris (CVE-2007-6750)
   - Esta vulnerabilidade de negação de serviço acontece ao abrir e manter diversas conexões com o servidor sem fecha-las, até esgotar os recursos do sistema,
      fazendo com que o serviço fique indisponivel para usuários que tentem acessar

| *Site completamente funcional antes da execução do ataque de negação de serviço com o exploit Slowloris* |
|:--:| 
| ![Imgur](https://imgur.com/ZlUyNGy.jpg) |

| *Procurando, configurando e executando o exploit Slowloris pelo Metasploit* |
|:--:| 
| ![Imgur](https://imgur.com/2vlSSMF.jpg) |

| *Durante a execução do ataque, o site fica inacessível* |
|:--:| 
| ![Imgur](https://imgur.com/PhIfOV4.jpg) |

#
### **Information Disclosure**
 - Vulnerabilidades de **Information Disclosure**, também chamadas de **Information Leakage** ou **Vazamento de Informações** são encontradas quando conseguimos fazer com que uma aplicação ou serviço nos revele informações que não deveria, como:
   -  *Dados de outros usuários, como logins e senhas*
   -  *Informações sobre o funcionamento interno do sistema*
   -  *Detalhes técnicos sobre o site e sua infraestrutura*
  
 - No arquivo **/phpinfo.php** do servidor web temos uma página repleta de informações que vão desde versões do sistema até exposição de configurações críticas

| *Arquivo ***/phpinfo.php*** expondo diversos parâmetros de configuração e informaçoes sensíveis sobre a máquina e sistema da aplicação*  |
|:--:| 
| ![Imgur](https://imgur.com/JkJ6CQi.jpg) |

#
### **Local File Inclusion (LFI) e Path Traversal**
  - Vulnerabilidades de LFI são usadas para acessar arquivos que normalmente não estariam acessiveis pelo servidor web, muitas vezes exploradas para ler arquivos críticos do sistema ou informações confidenciais, muitas vezes usados em conjunto com vulnerabilidades de ***Information Disclosure***, como detalhado no tópico anterior
  - Na página **http://192.168.3.80/mutilliae/index.php?page=index.php** podemos ver que o servidor acessa o arquivo **index.php** por um parâmetro na url, que pode ser alterado para que
     o servidor nos mostre arquivos sensíveis, como por exemplo o **/etc/passwd**
  - Url da exploração da vulnerabilidade: **http://192.168.3.80/mutillidae/index.php?page=../../../../../../../../etc/passwd**
  - Explorando as vulnerabilidades de **Path Traversal e Local File Inclusion** conseguimos ler um arquivo critico do sistema com todos os usuarios e suas permissões

| *Acessando o arquivo ***/etc/passwd*** utilizando as vulnerabilidades de LFI e Path Traversal*  |
|:--:| 
| ![Imgur](https://imgur.com/Ms3Vokt.jpg) |

#
## Crackeando o Hash fornecido
 - ***6b1628b016dff46e6fa35684be6acc96***
 - Primeiramente precisamos identificar qual é o algoritmo usado neste hash, para isso vou usar uma ferramenta online disponivel [aqui](https://hashes.com/en/tools/hash_identifier)
 - Com o hash identificado como MD5, precisamos usar uma ferramenta de brute force para crackear o hash e descobrir o plain-text.
 - Para o brute force vamos utilizar a ferramenta ***Hashcat*** e a wordlist ***probable-v2-top12000.txt***, lista com 12.000 senhas comuns, vazadas em dumps na internet.
 - Wordlist disponivel [aqui](https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/probable-v2-top12000.txt)
 - Hash crackeado, a palavra é "***summer***"

| *identificando o algoritmo do hash com o hash_identifier*  |
|:--:| 
| ![Imgur](https://imgur.com/pXBh1uH.jpg) |

| *Executando a ferramenta Hashcat e crackeando com sucesso o hash*  |
|:--:| 
| ![Imgur](https://imgur.com/Hrp9ZPU.jpg) |
