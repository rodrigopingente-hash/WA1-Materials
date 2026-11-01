# README — WA1 Secure Streaming

## 1. Descrição do projeto

Este projeto corresponde à primeira parte da solução 3S (*Secure Streaming Solution*), cujo objetivo é garantir uma comunicação segura entre um Proxy e um servidor de streaming.

O navegador acede ao Proxy através de HTTP, enquanto a comunicação entre o Proxy e o servidor é protegida com X25519, Ed25519, HKDF e AES-GCM. Foram testadas configurações AES com chaves de 128, 192 e 256 bits, bem como mecanismos de proteção contra alterações, repetição e reordenação de mensagens.

## 2. Requisitos

Para executar o projeto, é necessário:

- Windows 11;
- Java JDK 27 (OpenJDK);
- IntelliJ IDEA;
- Um navegador, como Chrome ou Edge.

Não é necessário instalar Maven ou Gradle.

## 3. Importação e compilação

1. Extrair o projeto para uma pasta no computador.
2. Abrir o IntelliJ IDEA e selecionar **File → Open**.
3. Escolher a pasta principal `WA1-Materials`.
4. Em **File → Project Structure**, configurar o JDK 27.
5. Confirmar que existem três módulos separados: `streamcommon-module`, `streamproxy-module` e `streamserver-module`.
6. Verificar que os módulos Proxy e Server dependem do módulo comum.
7. Executar **Build → Rebuild Project**.

É importante manter os módulos separados para evitar erros de compilação, como `duplicate class: HttpUtil`.

## 4. Execução do projeto

No IntelliJ, criar duas configurações de execução do tipo *Application*.

**Origin Server**

- Main class: `OriginSocketServer`
- Module: `streamserver-module`
- Program arguments: `8081 streamserver/media`

**Secure Proxy**

- Main class: `ProxySocketServer`
- Module: `streamproxy-module`
- Program arguments: `8080 localhost 8081`

Em ambas as configurações, o *Working directory* deve corresponder à localização dos ficheiros de configuração, das chaves e dos conteúdos multimédia. Na estrutura original, poderá ser necessário utilizar `$PROJECT_DIR$/WA1-Materials`.

Primeiro, iniciar o Origin Server e, de seguida, o Secure Proxy.

## 5. Reprodução do vídeo

Com os dois componentes em execução, abrir o navegador e aceder a:

`http://localhost:8080/`

O vídeo `sample.mp4` deverá ser reproduzido através do Proxy. Durante a transmissão, é possível acompanhar nas consolas os blocos recebidos, os dados encaminhados e as estatísticas da ligação.

## 6. Testes de segurança

Foram desenvolvidos e executados nove testes:

- `HandshakeMessageTest`
- `KeyDerivationTest`
- `KeyExchangeTest`
- `DigitalSignatureTest`
- `HandshakeProtocolTest`
- `HandshakeSecurityTest`
- `SecureHandshakeTest`
- `SecureRecordTest`
- `SecureChannelTest`

Estes testes verificam o estabelecimento do canal seguro, a troca e derivação de chaves, a autenticação e a proteção dos dados contra alterações e ataques de repetição. Todos foram executados com sucesso durante o desenvolvimento.

## 7. Configurações criptográficas

Os parâmetros criptográficos são definidos nos ficheiros `proxycrypto.config` e `sservercrypto.config`.

A implementação permite utilizar AES-GCM com chaves de 128, 192 ou 256 bits, sem alterar ou recompilar o código. Para mudar de configuração, basta editar os ficheiros XML e reiniciar os componentes.

As configurações do Proxy e do servidor devem ser compatíveis. Caso contrário, o handshake é rejeitado.

## 8. Problemas comuns

Se ocorrerem erros de compilação, deve verificar-se a configuração do JDK e dos módulos no IntelliJ.

Erros relacionados com ficheiros não encontrados podem resultar de um *Working directory* incorreto. Se a ligação for recusada, é necessário confirmar que o servidor está em execução na porta 8081.

Também é importante verificar se as portas 8080 e 8081 estão disponíveis e se as configurações criptográficas dos dois componentes são compatíveis.

## 9. Notas finais

O projeto inclui o código-fonte, os testes e os ficheiros necessários à execução. Recomenda-se testar a compilação e a reprodução do vídeo num computador diferente antes da apresentação.

As chaves privadas incluídas para demonstração não devem ser utilizadas em produção nem publicadas como credenciais reais.