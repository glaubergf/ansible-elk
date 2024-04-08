---
Projeto: ansible-elk
Descrição: Esse projeto automatiza a instalação e configuração dos produtos do Elastic Stack
           (Elasticsearch / Kibana / Logstash / Beats) em um servidor RockyLinux.
Autor: Glauber GF (mcnd2)
Data: 2024-04-07
---

# Automatizar com o Ansible a instalação e configuração do Elastic Stack no servidor Rocky Linux

![Image](https://github.com/glaubergf/ansible-elks/blob/main/images/elastic_observability_host_sup.png)

O **[Elastic Stack](https://www.elastic.co/pt/elastic-stack/)** (_também conhecido como ELK Stack_) é composto pelos seguintes produtos: _Elasticsearch_, _Kibana_, _Logstash_ e _Beats_. Com isso, podemos obter dados de maneira confiável e segura de qualquer fonte, em qualquer formato, depois, fazer buscas, análises e visualizações.

Esse projeto com o **[Ansible](https://docs.ansible.com/ansible/latest/getting_started/get_started_ansible.html)** foi implementado para automatizar a instalação e configuração do **Elastic Stack** no momento do provisionamento do um servidor **RockyLinux** com o Terraform. Segue o link para o projeto do Terraform **[terraform-libvirt-rocky-elk](https://github.com/glaubergf/terraform-libvirt-rocky-elk)** no GitHub.

# Ansible

O **[Ansible](https://docs.ansible.com/ansible/latest/getting_started/index.html)** fornece automação de código aberto que reduz a complexidade e funciona em qualquer lugar. Usar o Ansible permite automatizar praticamente qualquer tarefa. A organização e estruturação do projeto Ansible são fundamentais para garantir a eficiência e a manutenção do código.

Segue as divisões principais do projeto Ansible.
```
Playbooks:
São os scripts principais que definem as tarefas a serem executadas nos hosts gerenciados. Eles permitem uma orquestração detalhada da infraestrutura, controlando o número de máquinas a serem atualizadas simultaneamente.

Roles:
São uma forma de organizar o conteúdo dos playbooks, agrupando tarefas, variáveis e arquivos relacionados em unidades reutilizáveis. Isso facilita a manutenção e a reutilização do código.

Inventários:
São listas de hosts que o Ansible gerencia. Eles podem ser definidos como um diretório estruturado em vez de um único arquivo, facilitando a organização e a gestão dos hosts.

Variáveis:
São usadas para definir informações que podem variar entre diferentes ambientes ou hosts. Elas podem ser definidas no inventário, em arquivos de variáveis ou diretamente nos playbooks.

Plugins:
São extensões que permitem ao Ansible interagir com sistemas externos ou realizar tarefas específicas que não são cobertas pelos módulos padrão. Eles devem seguir diretrizes específicas para garantir a qualidade e a manutenção.
```
Atualmente o Ansible pertence a **[Red Hat](https://www.redhat.com/pt-br/technologies/management/ansible)**.

Pressupondo que você já tenha o **Ansible** e funcional, para executar o projeto, certifique-se que esteja dentro do diretório raíz do projeto, com isso, execute de uma vez só todo o projeto com o comando abaixo:
```
ansible-playbook -i hosts main.tf
```

Caso queira executar uma role de cada vez, execute o mesmo comando acima mas com a opção "-t" ( --tags ) seguido do nome da tag que foi dado nas tarefas da role. 
```
ansible-playbook -i hosts main.tf -t dnf
```

Pode também antes de aplicar em definitivo, executar o mesmo  comando acima mas com a opção "-C" ( --check ), assim será apenas checado cada tarefa sem de fato executar.

```
ansible-playbook -i hosts main.yml -t dnf -C
```

Para saber mais opções do Ansible, execute com a opção "-h" ( --help) para mostrar a ajuda para o uso de cada opção.

```
ansible --help
```

## Playbook

O **Playbook** define uma série de **roles** que serão aplicadas no alvo (hots). Cada role é associada a uma **tag** específica, permitindo que as **tarefas** sejam executadas de forma seletiva com base nessas tags.

Temos as seguintes **Roles** abaixo:
```
motd:
Provavelmente responsável por configurar a mensagem do dia (Message of the Day) nos servidores.

dnf:
Pode ser relacionada à gestão de pacotes no sistema operacional, utilizando o gerenciador de pacotes DNF (Dandified Yum).

elasticsearch:
Configuração do Elasticsearch, um mecanismo de busca e análise de dados.

kibana:
Configuração do Kibana, uma interface de usuário para visualizar dados do Elasticsearch.

logstash:
Configuração do Logstash, uma ferramenta de processamento de dados de log.

metricbeat:
Configuração para o Metricbeat, um agente de coleta de métricas para o Elastic Stack.
```
Cada role é executada em sequência, permitindo que as configurações sejam aplicadas de forma organizada e modular. As tags associadas a cada role facilitam a execução de tarefas específicas, se necessário, sem a necessidade de executar todo o playbook.

## Roles

Como informado acima, temos 6 roles. Sendo assim, vamos ver os aspectos de cada taks (tarefas) em cada role.

### motd

* _config_motd.yml_

O arquivo "config_motd.yml" é responsável por configurar a Mensagem do Dia (Message of the Day - MOTD) em sistemas operacionais baseados em Unix. A MOTD é uma mensagem que é exibida para os usuários quando eles fazem login em um sistema. Essa role utiliza um script shell para realizar a configuração da MOTD.

### dnf

* _install_packages.yml_

O arquivo "install_packages.yml" realiza uma série de tarefas relacionadas à gestão de pacotes em sistemas baseados em Red Hat, utilizando o gerenciador de pacotes DNF. Segue um resumo das tarefas realizadas:
```
Limpeza de todos os repositórios do sistema:
Utiliza o comando dnf --enablerepo=* clean all para limpar todos os repositórios, removendo pacotes baixados e metadados antigos.

Atualização de todos os pacotes do sistema:
Atualiza todos os pacotes instalados para as últimas versões disponíveis, garantindo que o sistema esteja atualizado.

Atualização do cache dos repositórios do sistema:
Atualiza o cache dos repositórios para garantir que as informações sobre os pacotes disponíveis estejam atualizadas.

Instalação do repositório EPEL e pacotes específicos:
Instala o repositório EPEL (Extra Packages for Enterprise Linux), que fornece pacotes extras e as últimas versões de pacotes que não estão disponíveis nos repositórios padrão de distribuições Linux baseadas em Red Hat. Além disso, instala os pacotes bind-utils e net-tools, que são uma coleção de utilitários de rede.

Instalação de mais pacotes específicos:
Instala uma lista de pacotes específicos, incluindo bash-completion, firewalld, nano, wget, nginx, e htop, garantindo que esses pacotes estejam instalados e atualizados.

Atualização do cache dos repositórios do sistema:
Realiza uma nova atualização do cache dos repositórios para garantir que as informações sobre os pacotes disponíveis estejam atualizadas após a instalação dos pacotes específicos.

Habilitação e reinicialização do serviço Nginx:
Habilita o serviço Nginx e o reinicia, garantindo que o servidor web esteja ativo e funcionando corretamente após a instalação.
```
Este arquivo de configuração é uma parte essencial da role dnf, garantindo que o sistema esteja configurado corretamente com os pacotes necessários e que os serviços essenciais, como o Nginx, estejam ativos e funcionando.

### elasticsearch

* _install_elasticsearch.yml_

O arquivo "install_elasticsearch.yml" é responsável por automatizar a instalação e configuração do Elasticsearch em um sistema baseado em RPM, como CentOS ou Red Hat. Segue um resumo das principais tarefas realizadas por este arquivo:
```
Instalação e Configuração do Firewalld:
Instala o pacote firewalld usando o gerenciador de pacotes dnf.
Habilita o firewalld para iniciar automaticamente com o sistema.
Inicia o serviço firewalld.
Verifica e imprime o estado do firewalld.
Permite o tráfego HTTP/HTTPS na zona padrão do firewalld e recarrega o serviço.

Instalação do Java:
Baixa o binário do Java a partir de uma URL específica.
Instala o Java usando o comando rpm.
Verifica e imprime a versão do Java instalada.

Configuração do Repositório do Elasticsearch:
Importa a chave GPG pública do Elasticsearch para o gerenciador de pacotes RPM.
Adiciona o repositório do Elasticsearch ao sistema.
Atualiza o cache dos repositórios do sistema.

Instalação e Configuração do Elasticsearch:
Instala o pacote Elasticsearch.
Habilita e inicia o serviço Elasticsearch.
Reseta a senha do usuário elastic (administrador do Elasticsearch) e salva a senha em um arquivo.

Configuração de Segurança e Acesso:
Restringe o acesso externo ao Elasticsearch, alterando a configuração "network.host" para "localhost" no arquivo "elasticsearch.yml".
Desativa as funcionalidades de segurança do Elasticsearch, alterando a configuração "xpack.security.enabled" para "false" no arquivo "elasticsearch.yml".
Permite o tráfego na porta "TCP 9200" através do firewalld.

Reinicialização e Verificação do Elasticsearch:
Reinicia o serviço Elasticsearch para aplicar as alterações.
Verifica se o Elasticsearch está "respondendo a solicitações HTTP simples" usando o comando curl e salva a saída em um arquivo.
```
Este arquivo de configuração é uma parte essencial para a implantação automatizada do Elasticsearch em ambientes gerenciados pelo Ansible, garantindo que todas as dependências, como o Java e o firewalld, estejam corretamente instaladas e configuradas, além de configurar o Elasticsearch de acordo com as necessidades específicas do ambiente de implantação.

### kibana

* _install_kibana.yml_

O arquivo "install_kibana.yml" realiza uma série de tarefas para instalar e configurar o Kibana em um sistema baseado em RPM, como CentOS ou RHEL. Segue um resumo das principais ações realizadas por este arquivo:
```
Instalação do pacote Kibana:
Utiliza o gerenciador de pacotes dnf para instalar o pacote Kibana, garantindo que o Kibana esteja presente no sistema.

Configuração do host do Kibana:
Modifica o arquivo de configuração /etc/kibana/kibana.yml para definir o host do servidor Kibana para um IP específico (192.100.20.200), permitindo que o Kibana seja acessado a partir desse endereço IP.

Ativação e inicialização do serviço Kibana:
Configura o serviço Kibana para iniciar automaticamente no boot do sistema e inicia o serviço imediatamente.

Criação de um usuário administrativo para o Kibana:
Utiliza o comando openssl para gerar uma senha segura para um usuário administrativo (kibanaadmin) e armazena as credenciais no arquivo /etc/nginx/htpasswd.users, que será usado para autenticação no Nginx.

Permissão de tráfego na porta TCP 5601:
Configura o firewall para permitir o tráfego na porta 5601, que é a porta padrão do Kibana, permitindo o acesso à interface web do Kibana de outras máquinas.

Configuração do Nginx para autenticação:
Cria um arquivo de configuração do Nginx que configura o Nginx para autenticar o acesso à interface web do Kibana usando as credenciais armazenadas em "/etc/nginx/htpasswd.users".

Verificação e reinicialização do Nginx:
Verifica a configuração do Nginx para erros de sintaxe e reinicia o serviço Nginx se a verificação for bem-sucedida, garantindo que as novas configurações entrem em vigor.
```
Este arquivo de configuração é uma parte essencial para a instalação e configuração do Kibana em um ambiente de produção, garantindo que o Kibana esteja corretamente instalado, configurado para ser acessado de forma segura e que o serviço esteja pronto para uso.

### logstash

* _install_logstash.yml_

O arquivo "install_logstash.yml" tem como objetivo automatizar a instalação e configuração do Logstash em um servidor. Segue um resumo das principais tarefas realizadas por este arquivo:
```
Instalação do pacote Logstash:
Utiliza o gerenciador de pacotes dnf para instalar o Logstash, garantindo que a versão mais recente esteja disponível no servidor.

Adição de um certificado SSL:
Modifica o arquivo de configuração do OpenSSL para incluir um certificado SSL baseado no endereço IP do servidor ELK, permitindo a comunicação segura entre o Logstash e outros serviços.

Geração de um certificado autoassinado:
Cria um certificado autoassinado válido por 365 dias usando o OpenSSL, que é necessário para a comunicação segura entre o Logstash e os clientes que enviam logs.

Configuração de arquivos de entrada (Input), saída (Output) e filtro (Filter) do Logstash:
Define as configurações de entrada, saída e filtro do Logstash, incluindo a configuração para receber logs via Beats, enviar para Elasticsearch e aplicar filtros específicos para os logs do syslog.

Habilitação e inicialização do serviço Logstash:
Configura o Logstash para iniciar automaticamente no boot e inicia o serviço imediatamente.

Teste da configuração do Logstash:
Executa um teste de configuração do Logstash para garantir que não há erros antes de colocá-lo em produção.

Permissão de tráfego na porta TCP 5044:
Configura o firewall para permitir tráfego na porta 5044, que é usada pelo Logstash para receber logs.

Cópia de certificados e arquivos:
Copia o certificado autoassinado gerado para um diretório local e busca arquivos .txt no servidor ELK para copiar para o host local do projeto.
```
Este arquivo de configuração é uma parte essencial da automação de infraestrutura, permitindo que os administradores de sistemas instalem e configurem o Logstash de forma consistente e eficiente em múltiplos servidores.

### metricbeat

* _install_metricbeat.yml_

O arquivo de configuração install_metricbeat.yml para a role metricbeat no Ansible é responsável por automatizar a instalação e configuração do Metricbeat em um cliente Debian. Aqui está um resumo das principais tarefas realizadas por este arquivo:
```
Copia do Certificado SSL:
Copia um certificado SSL autoassinado do servidor Rocky Linux 9 para o cliente Debian. Isso é feito para garantir a comunicação segura entre o cliente e o servidor.

Baixando a Chave de Assinatura do Elasticsearch:
Baixa a chave de assinatura do Elasticsearch para garantir a autenticidade dos pacotes baixados.

Adicionando o Repositório Elasticsearch:
Configura o repositório do Elasticsearch para facilitar a instalação do Metricbeat.

Instalando o pacote apt-transport-https:
Garante que o sistema possa acessar repositórios HTTPS.

Atualizando Repositórios do Sistema:
Atualiza a lista de pacotes disponíveis para garantir que o sistema tenha acesso à versão mais recente do Metricbeat.

Instalando o Metricbeat:
Instala o pacote Metricbeat no sistema.

Habilitando e Iniciando o Serviço Metricbeat:
Configura o Metricbeat para iniciar automaticamente com o sistema e inicia o serviço.

Configurando o Metricbeat:
Realiza várias configurações no arquivo metricbeat.yml, incluindo a alteração do host do Elasticsearch, a habilitação do módulo "system", e a configuração de credenciais para o Elasticsearch.

Copiando e Extraindo a Senha do Elasticsearch:
Copia um arquivo de senha do host local para o cliente remoto e extrai a senha para uso na configuração do Metricbeat.

Habilitando o Módulo "system" do Metricbeat:
Habilita o módulo "system" do Metricbeat para coletar métricas do sistema.

Carregando Painéis do Kibana:
Executa o comando metricbeat setup para carregar os painéis do Kibana, se necessário.

Reiniciando o Serviço Metricbeat:
Reinicia o serviço Metricbeat para aplicar todas as configurações.
```
Este arquivo de configuração é uma parte essencial da automação de infraestrutura, permitindo a instalação e configuração rápida e consistente do Metricbeat em vários clientes Debian, facilitando a coleta e o envio de métricas para o Elasticsearch para análise e visualização no Kibana.

# Licença

**GNU General Public License** (_Licença Pública Geral GNU_), **GNU GPL** ou simplesmente **GPL**.

[GPLv3](https://www.gnu.org/licenses/gpl-3.0.html)

------

Copyright (c) 2024 Glauber GF (mcnd2)

Este programa é um software livre: você pode redistribuí-lo e/ou modificar
sob os termos da GNU General Public License conforme publicada por
a Free Software Foundation, seja a versão 3 da Licença, ou
(à sua escolha) qualquer versão posterior.

Este programa é distribuído na esperança de ser útil,
mas SEM QUALQUER GARANTIA; sem mesmo a garantia implícita de
COMERCIALIZAÇÃO ou ADEQUAÇÃO A UM DETERMINADO FIM. Veja o
GNU General Public License para mais detalhes.

Você deve ter recebido uma cópia da Licença Pública Geral GNU
junto com este programa. Caso contrário, consulte <https://www.gnu.org/licenses/>.

*

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>