
1. DESCRIÇÃO

Este projeto implementa a primeira parte da solução 3S, acrescentando um canal
seguro à comunicação entre um Secure Proxy e um Secure Stream Server. O navegador
acede ao Proxy através de HTTP local; o Proxy recebe os blocos de vídeo do
servidor através de um canal protegido e encaminha os dados para reprodução.

Mecanismos implementados: troca de chaves X25519, autenticação do servidor com
Ed25519, derivação de chaves HKDF e cifragem autenticada AES-GCM. Foram testados
os tamanhos de chave AES de 128, 192 e 256 bits. O canal também verifica a
sequência dos registos, rejeitando modificações, repetições e reordenações.

NOTA: A ligação HTTP entre o navegador e o Proxy não é protegida pelo canal
criptográfico implementado neste trabalho.

2. REQUISITOS

- Windows 11 (ambiente utilizado nos testes).
- JDK 27 (por exemplo, Eclipse Temurin/OpenJDK).
- IntelliJ IDEA.
- Navegador web, como Chrome ou Edge.
- Não é necessário Maven ou Gradle para a estrutura IntelliJ utilizada.

Confirmar a instalação do JDK numa consola:

    java -version
    javac -version

Ambos devem indicar a versão 27.

3. ESTRUTURA DO PROJETO

A distribuição original pode apresentar uma pasta WA1-Materials exterior e outra
pasta WA1-Materials no seu interior:

    WA1-Materials/                   (raiz exterior do projeto)
      .idea/
      streamcommon-module/
      streamproxy-module/
      streamserver-module/
      streamproxy/
      streamserver/
      WA1-Materials/                 (pasta interior)
        streamcommon/               (código partilhado)
        streamproxy/                (código do Proxy)
        streamserver/               (código do Server e media/)

Conservar a estrutura relativa dos ficheiros, incluindo os XML de configuração,
as chaves necessárias à demonstração e o ficheiro de vídeo sample.mp4.
Não publicar chaves privadas reais num repositório público. As chaves de teste
incluídas na distribuição devem ser consideradas apenas material de demonstração.

4. IMPORTAR E COMPILAR NO INTELLIJ IDEA

1) Extrair o ZIP para uma pasta local, por exemplo C:\WA1-Defesa.
2) Abrir o IntelliJ IDEA e selecionar File > Open.
3) Selecionar a pasta WA1-Materials EXTERIOR que contém a pasta .idea.
4) Em File > Project Structure > Project, configurar Project SDK = JDK 27.
5) Em Project Structure > Modules, confirmar a existência de três módulos
   independentes: streamcommon-module, streamproxy-module e streamserver-module.
6) Verificar as raízes de código-fonte:
      streamcommon-module -> WA1-Materials/streamcommon
      streamproxy-module  -> WA1-Materials/streamproxy
      streamserver-module -> WA1-Materials/streamserver
   (os caminhos acima referem-se à pasta WA1-Materials INTERIOR).
7) Confirmar que os módulos Proxy e Server têm dependência do módulo comum.
8) Executar Build > Rebuild Project e verificar se a compilação termina sem erros.

IMPORTANTE: Se o IntelliJ importar as três pastas de código-fonte como um único
módulo, poderá surgir o erro 'duplicate class: HttpUtil'. Existem classes
HttpUtil em streamproxy e streamserver; as pastas devem ser compiladas em
módulos separados. Não eliminar os ficheiros HttpUtil.java para corrigir o erro.

5. CONFIGURAR E EXECUTAR O SERVIDOR

Em Run > Edit Configurations > + > Application, criar:

    Name:              Origin Server
    Main class:        OriginSocketServer
    Module/classpath:  streamserver-module
    Program arguments: 8081 streamserver/media
    JRE:               Project SDK (27)
    Working directory: diretório que contém streamserver/keys,
                       streamserver/sservercrypto.config e streamserver/media

ATENÇÃO: Na estrutura distribuída, estes caminhos relativos devem ser verificados
no computador de destino. Se os ficheiros se encontrarem na pasta interior,
utilizar como Working directory:

    $PROJECT_DIR$/WA1-Materials

Se estiverem efetivamente na raiz exterior, utilizar $PROJECT_DIR$.
O essencial é que o caminho relativo streamserver/media aponte para a pasta
que contém sample.mp4 e que as chaves/configurações sejam encontradas.

Executar Origin Server e manter o processo ativo na porta 8081.

6. CONFIGURAR E EXECUTAR O PROXY

Em Run > Edit Configurations > + > Application, criar:

    Name:              Secure Proxy
    Main class:        ProxySocketServer
    Module/classpath:  streamproxy-module
    Program arguments: 8080 localhost 8081
    JRE:               Project SDK (27)
    Working directory: diretório que contém streamproxy/proxycrypto.config
                       e as chaves utilizadas pelo Proxy

Na estrutura com ficheiros na pasta interior, experimentar:

    $PROJECT_DIR$/WA1-Materials

O Working directory deve ser consistente com os caminhos relativos usados
pelo código. Executar Secure Proxy e manter também este processo ativo.

7. REPRODUZIR O VÍDEO

Com o servidor e o Proxy em execução:

1) Abrir Chrome ou Edge.
2) Aceder a http://localhost:8080/
3) Iniciar a reprodução do vídeo sample.mp4.
4) Verificar as mensagens nas consolas do Proxy e do servidor.

O navegador pode solicitar apenas uma parte do ficheiro, originando a resposta
HTTP 206 Partial Content. Por esse motivo, o volume transferido pode ser
inferior ao tamanho total de sample.mp4 sem representar perda de dados.

8. TESTES DE SEGURANÇA

No IntelliJ, localizar e executar individualmente os programas de teste:

    HandshakeMessageTest
    KeyDerivationTest
    KeyExchangeTest
    DigitalSignatureTest
    HandshakeProtocolTest
    HandshakeSecurityTest
    SecureHandshakeTest
    SecureRecordTest
    SecureChannelTest

Os testes abrangem mensagens do handshake, X25519, Ed25519, HKDF, autenticação,
proteção dos registos, integridade, replay, ordem dos blocos e canal TCP seguro.
Estes nove testes foram executados com sucesso na validação do projeto.

9. ALTERAR A CONFIGURAÇÃO CRIPTOGRÁFICA

Editar os ficheiros XML correspondentes ao Proxy e ao Server:

    streamproxy/proxycrypto.config
    streamserver/sservercrypto.config

Manter parâmetros compatíveis em ambos os extremos. A implementação foi testada
com AES-GCM e tamanhos de chave de 128, 192 e 256 bits, sem recompilação.
Depois de alterar os XML, reiniciar os dois processos.

Para demonstrar rejeição de incompatibilidade, configurar temporariamente
KeySize=128 num extremo e KeySize=256 no outro. O handshake deverá falhar.
Restaurar depois a configuração original (AES-256-GCM em ambos).

10. MÉTRICAS E OBSERVAÇÕES

Depois de uma transferência, a consola do Proxy apresenta métricas como:

- Número de registos DATA cifrados recebidos e autenticados.
- Número de blocos decifrados encaminhados ao navegador.
- Volume de dados multimédia autenticados e encaminhados.
- Throughput observado da transferência.
- Estado HTTP e conclusão da resposta do servidor.

Os valores variam consoante os pedidos do navegador e as condições da execução.

11. RESOLUÇÃO DE PROBLEMAS

'JDK not configured' ou falhas de compilação:
    Verificar Project SDK e Module SDK em Project Structure.

'duplicate class: HttpUtil':
    Verificar se streamproxy e streamserver estão em módulos separados.

'FileNotFoundException':
    Rever o Working directory e os caminhos para XML, chaves e media.

'Connection refused':
    Confirmar que Origin Server está ativo na porta 8081 antes de usar o Proxy.

'Address already in use':
    Confirmar se as portas 8080 ou 8081 estão ocupadas. Em CMD:
        netstat -ano | findstr :8080
        netstat -ano | findstr :8081

'Incompatible cryptographic configuration':
    Confirmar a compatibilidade dos parâmetros nos dois ficheiros XML.

Falha na autenticação Ed25519:
    Confirmar que a chave pública confiável corresponde à identidade do servidor.

12. NOTAS PARA A ENTREGA

- Incluir código-fonte, ficheiros de configuração, documentação e testes.
- Não incluir pastas de compilação temporárias como out/.
- Confirmar a importação e a execução a partir de uma cópia limpa do projeto.
- Nunca divulgar chaves privadas de produção ou credenciais reais.

Este README descreve o procedimento previsto para a distribuição IntelliJ.
As configurações de execução e os caminhos devem ser confirmados no computador
utilizado na apresentação, sobretudo se a estrutura do repositório for alterada.
