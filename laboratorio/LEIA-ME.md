# Laboratório do Radar: treino para quem está começando

Cinco exercícios num contêiner descartável com pacotes vulneráveis de verdade. Aqui errar não custa nada: se algo der errado, apague e recomece. Tempo total: de 40 a 60 minutos.

**Precisa de:** um computador com Docker (ou Podman) e internet. **Nunca** rode o laboratório num servidor de produção.

```bash
bash laboratorio/lab.sh preparar     # cria o contêiner radar-lab (1 a 3 minutos)
bash laboratorio/lab.sh entrar       # abre um terminal dentro dele, em /radar
bash laboratorio/lab.sh conferir 1   # depois de cada exercício, num OUTRO terminal fora do contêiner
bash laboratorio/lab.sh gabarito 1   # resposta comentada, se travar
bash laboratorio/lab.sh limpar       # apaga tudo; preparar recomeça do zero
```

Dentro do contêiner você já é root, então os comandos aparecem sem `sudo`. Num servidor de verdade, use `sudo` onde o guia indicar.

## Antes de começar: três ideias

- **CVE** é o número de uma falha conhecida. **Correção** é a versão do pacote que a distribuição publicou sem a falha.
- **VULNERÁVEL** no Radar quer dizer: existe correção na distro e o pacote instalado é mais antigo que ela. **SEM CORREÇÃO** quer dizer: a falha é conhecida e ainda não há pacote corrigido.
- A **decisão** (Agir agora, Agir em breve, Acompanhar de perto, Acompanhar) diz a urgência. Ela combina exploração ativa (KEV), probabilidade de exploração (EPSS), gravidade e a importância do sistema para a universidade.

## Exercício 1: ler a verificação

Objetivo: entender a saída do script que só lê o sistema.

1. `bash radar-verificar.sh`
2. Ache o grupo **VULNERÁVEL** e conte os itens.
3. Na linha do Kerberos (krb5), ache a versão instalada e a mínima corrigida. Note o aviso (USN) e a decisão.
4. Rode também `bash radar-verificar.sh --todos` e veja os itens OK e não instalados.

Conferir: `bash laboratorio/lab.sh conferir 1`

## Exercício 2: simular a correção

Objetivo: ver o que a correção faria, sem mudar nada.

1. `bash radar-corrigir.sh --simular`
2. Leia os passos: diagnóstico, ponto de restauração, atualização dos índices, correção item a item, mitigações, serviços, conferência.
3. Na correção do krb5, observe o comando `apt-get install --only-upgrade …`: quais pacotes ele toca?

Conferir: `bash laboratorio/lab.sh conferir 2`

## Exercício 3: corrigir de verdade

Objetivo: aplicar a correção do Kerberos com ponto de restauração.

1. `bash radar-corrigir.sh`
2. Responda **s** ao snapshot (aqui é treino), à cópia do `/etc`, ao `apt-get update` e ao `dpkg-repack`.
3. Na lista de correções, responda **s** só para o Kerberos e **n** para os outros itens.
4. Anote o caminho do ponto de restauração mostrado no fim.
5. Rode `bash radar-verificar.sh` de novo. Se o krb5 aparecer como ATENÇÃO, a correção foi aplicada, mas a distro ainda tem CVEs do krb5 sem correção.

Conferir: `bash laboratorio/lab.sh conferir 3`

## Exercício 4: desfazer (rollback)

Objetivo: voltar a versão anterior, como se a atualização tivesse quebrado um serviço.

1. `bash radar-rollback.sh`
2. Escolha o ponto de restauração do exercício 3.
3. No item do Kerberos, escolha **d** (reinstala os pacotes salvos), confirme com **s** e responda **n** à pergunta sobre fixar a versão. Pule os outros itens com **p**.
4. Rode `bash radar-verificar.sh`: o krb5 voltou a ficar VULNERÁVEL.

Conferir: `bash laboratorio/lab.sh conferir 4`

## Exercício 5: quando não há correção

Objetivo: decidir o que fazer com um item SEM CORREÇÃO.

1. `bash radar-verificar.sh` e ache o Node.js no grupo **SEM CORREÇÃO**.
2. No painel, abra o item do Node.js e leia **Mitigação** e **Decisão**. Se o botão **Explicar para o meu contexto** aparecer, use-o.
3. Pense: o que a equipe faz até a distro publicar o pacote?

Conferir: `bash laboratorio/lab.sh conferir 5`

## Depois do laboratório

- Leia o tour do painel (botão **Tour guiado**).
- Pratique a verificação de imagens: `bash radar-verificar.sh --imagem ubuntu:26.04` no seu computador.
- Em produção: rode primeiro a verificação, depois `--simular`, e só então a correção, numa janela combinada e com snapshot.
