# Linux Kernel Exploit — AF_ALG

Exploit experimental desenvolvido em Bash + C para pesquisa e análise de comportamento do kernel Linux.
O projeto explora a interface **AF_ALG** do kernel e utiliza operações de baixo nível, como `splice()`, sockets e pipes, para realizar a manipulação necessária durante a exploração.

> ⚠️ Este código foi desenvolvido para ambiente de pesquisa e laboratório. A execução pode comprometer o sistema utilizado. Não execute em servidores de produção ou em máquinas que contenham dados importantes.

## Funcionamento

O projeto é iniciado através de um script Bash.
Antes de executar o código principal, o script procura um diretório temporário adequado entre:

```text
/dev/shm
/tmp
```

O diretório precisa permitir escrita e execução. Montagens configuradas com `noexec` ou somente leitura são ignoradas.
Depois, o script:

1. cria um diretório temporário;
2. compila o código C diretamente com `gcc`;
3. gera o binário dentro do diretório temporário;
4. executa o binário;
5. remove os arquivos temporários ao finalizar.

O código C realiza a parte principal da exploração.

## Componentes utilizados

### Bash

Responsável por preparar o ambiente e executar o código compilado.
Entre outras coisas, o script verifica:

* diretórios temporários disponíveis;
* permissões de escrita;
* opção `noexec`;
* opção `ro`;
* criação e limpeza do diretório temporário;
* compilação do código C.

### C

A parte em C trabalha diretamente com interfaces do kernel Linux.
São utilizadas principalmente:

* `AF_ALG`;
* sockets `SOCK_SEQPACKET`;
* `setsockopt()`;
* `sendmsg()`;
* `splice()`;
* pipes;
* file descriptors;
* `zlib`.

## Payload

O payload utilizado pelo exploit está armazenado no código em formato hexadecimal e comprimido com **zlib**.
Durante a execução:

```text
payload hexadecimal
        ↓
conversão para bytes
        ↓
descompressão
        ↓
buffer em memória
        ↓
processamento pelo exploit
```

O payload é processado em pequenos blocos durante a etapa de exploração.

## AF_ALG

O `AF_ALG` é uma interface do Linux que permite que aplicações em espaço de usuário utilizem algoritmos criptográficos disponibilizados pelo kernel.
Neste projeto, a interface é utilizada através de um socket:

```c
socket(AF_ALG, SOCK_SEQPACKET, 0);
```

Em seguida, o código configura o algoritmo criptográfico e os parâmetros necessários para a operação.
Essa parte é importante para o funcionamento do exploit, pois o comportamento explorado está relacionado ao processamento realizado pelo kernel.

## splice()

O código também utiliza a syscall `splice()`.
Ela permite movimentar dados entre file descriptors sem precisar copiar os dados normalmente através do espaço de usuário.
No projeto, ela é utilizada para transferir dados entre:

```text
arquivo → pipe → socket
```

Isso permite trabalhar com os dados diretamente através dos descritores envolvidos na exploração.

## Arquivo alvo

O código abre:

```text
/usr/bin/su
```

Esse arquivo é utilizado como alvo durante a exploração.
Por esse motivo, **a execução do projeto pode alterar o comportamento do sistema e comprometer a máquina**.

## Dependências

Para compilação, o ambiente precisa possuir:
* Linux;
* Bash;
* GCC;
* zlib;
* headers de desenvolvimento do Linux;
* headers de desenvolvimento do zlib.
Em distribuições baseadas em Debian, por exemplo, os pacotes necessários normalmente incluem o compilador e os headers de desenvolvimento correspondentes.

## Ambiente de teste

O recomendado é executar o projeto somente em uma máquina virtual ou laboratório isolado.
Uma configuração adequada para pesquisa seria:

```text
Linux VM
 ├── snapshot antes do teste
 ├── sem dados importantes
 ├── acesso controlado
 └── rede isolada
```

Dessa forma, caso a exploração provoque comportamento inesperado ou corrupção do sistema, o ambiente pode ser restaurado.

## Limitações

O exploit depende de detalhes específicos da implementação do kernel.
Por isso, o fato de o código compilar não significa que ele funcionará em qualquer versão do Linux.
O resultado pode variar conforme:

* versão do kernel;
* arquitetura;
* distribuição;
* configurações de segurança;
* módulos disponíveis;
* permissões;
* implementação das interfaces utilizadas.

## Detecção

Do ponto de vista defensivo, alguns comportamentos interessantes para monitoramento são:

* compilação inesperada de binários;
* execução de binários criados em `/tmp` ou `/dev/shm`;
* acesso incomum a `/usr/bin/su`;
* utilização inesperada de `AF_ALG`;
* chamadas `splice()` por processos incomuns;
* criação de pipes e sockets em sequência;
* execução inesperada de `su`;
* alterações suspeitas envolvendo binários privilegiados.

## Objetivo

O objetivo deste projeto é estudar uma técnica de exploração envolvendo o kernel Linux e entender como diferentes interfaces de baixo nível podem ser combinadas durante uma exploração.
O código pode ser utilizado como material de estudo para:

* segurança de sistemas Linux;
* pesquisa de vulnerabilidades;
* análise de kernel;
* desenvolvimento de detecções;
* testes em laboratório;
* pesquisa de técnicas de exploração.

## Licença

Projeto experimental destinado a pesquisa e estudos de segurança.
Utilize somente em ambientes nos quais você tenha autorização para realizar testes.
