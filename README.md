API OF https://golive.nemtudo.me

API URL: https://apigolive.nemtudo.me

Front GitHub:
https://github.com/Nem-Tudo/group-sharescreen

## Vários núcleos (node:cluster)

Node roda em uma thread só, então uma única instância desta API usa um núcleo
do processador e ignora o resto da máquina. `server/main.ts` resolve isso
bifurcando na largada: o processo primário (`server/clusterPrimary.ts`) não
atende nada — ele só sobe um worker por núcleo, cada um rodando o mesmo
`server/index.ts` de sempre, e fica ali supervisionando e repassando mensagens
entre eles. O sistema operacional distribui as conexões entre os workers, na
mesma porta, sem mudar nada para o front nem para o proxy reverso.

| Variável | Para quê |
| --- | --- |
| `CLUSTER_WORKERS` | Quantos workers subir. Padrão: um por núcleo disponível (`availableParallelism`, que respeita o limite de CPU do container). **`1` desliga o cluster** — o servidor volta a ser um processo só, exatamente como antes |
| `CLUSTER_SCHEDULING` | `rr` (round-robin) ou `none` (o SO decide). Padrão do Node: round-robin em tudo menos Windows. Só mexa se estiver desenvolvendo no Windows e quiser distribuição de verdade entre os workers |

Cada worker é um processo Node inteiro: conta memória vezes o número de
workers (o driver do Mongo é carregado em cada um).
Em container apertado, prefira fixar `CLUSTER_WORKERS` em vez de deixar no
automático.

### O estado continua sendo um só

O ponto delicado é que duas pessoas na mesma sala quase nunca caem no mesmo
worker. Para que isso não apareça em lugar nenhum, **cada worker mantém uma
réplica completa do estado do cluster** (`server/signaling.ts`): `clients`,
`clientsById` e `rooms` valem para o cluster inteiro, não para o processo.
As conexões que o worker realmente atende carregam o socket de verdade; as
dos outros workers estão lá também, como `ClientInfo` normais cujo socket é um
`RemoteSocket` que encaminha o que for escrito para o dono da conexão.

É isso que faz o resto do arquivo continuar valendo sem mudança: o contador de
gente online, a lista de participantes, `GET /stats`, `GET /rooms`,
`GET /admin/rooms`, o chat, as fontes de vídeo, a reserva de nome dentro da
sala e o repasse de sinais WebRTC não sabem — nem precisam saber — que metade
dos sockets que estão percorrendo vive em outro processo.

Toda escrita é replicada pelo worker que atendeu a mensagem, e só ele executa
os efeitos colaterais (gravar no Redis/Mongo, creditar tempo de chamada,
contar a métrica). As réplicas apenas atualizam memória, então cada gravação
continua tendo uma origem só, como quando havia um processo apenas.

O que mais anda por esse mesmo canal:

- **Estado do site** — aviso/banner e suas estatísticas, anúncios de parceiro
  e as deles, lista de apoiadores: são editados por rota HTTP, que chega em um
  worker só (`clusterEvent(...)` em `signaling.ts`).
- **Moderação e contas** — banimentos, filtro de palavras, o interruptor do
  anti-spam (`moderationStore.ts`) e o índice de nomes reservados por conta
  (`accountStore.ts`), que é o que decide se um nome pode ser usado.
- **Limites de requisição HTTP** — `httpRateLimitStore.ts` compartilha os
  contadores do `@fastify/rate-limit`; sem isso, N workers multiplicariam por
  N todo limite por rota. Os limitadores de mensagem do WebSocket
  (`rateLimiter.ts`) não precisam disso: a chave deles é a conexão, que vive
  inteira em um worker só — a exceção é o contador de violações para auto-ban,
  que é por IP e por isso também é replicado.
- **`GET /metrics`** — um scrape cai em um worker qualquer, então o primário
  junta os registries de todos (`prom-client`). Os gauges alimentados por
  `registerStatsProvider` já são do cluster inteiro em cada worker, por causa
  da replicação, e por isso são agregados como `first` em vez de somados.

Se um worker morre, o primário avisa os outros, indica **um** deles para dar
baixa nas conexões que estavam lá (creditando tempo, passando a posse da sala,
mandando o `peer-left`) e sobe um substituto. O substituto pede o estado atual
antes de começar a aceitar conexões — sem isso ele nasceria sem saber de
nenhuma sala em andamento e criaria uma segunda sala vazia para quem caísse
nele.

### Enxergando os workers

O primário mantém a lista de quem está de pé e a empurra para todos os workers
sempre que muda (worker subiu, caiu, parou de escutar). Cada worker guarda essa
lista em memória — `server/clusterInfo.ts` —, então tanto o `/health` quanto as
métricas respondem sem ida e volta pelo IPC.

`GET /health` continua devolvendo `ok` e `CURRENT_ID` como sempre; o campo
`cluster` é aditivo:

```json
{
  "ok": true,
  "CURRENT_ID": "5efb92ce-...",
  "cluster": {
    "enabled": true,
    "servedBy": { "id": 3, "pid": 5572 },
    "online": 3,
    "configured": 3,
    "restarts": 0,
    "primaryPid": 25120,
    "workers": [
      { "id": 1, "pid": 10796, "startedAt": 1787988123152, "listening": true, "uptimeSeconds": 8 }
    ]
  }
}
```

`servedBy` é o worker que atendeu **aquela** requisição — como o balanceamento
é por conexão, chamadas seguidas caem em workers diferentes, e é assim que dá
para ver a distribuição na unha. `online` abaixo de `configured` significa que
alguém está subindo ou sendo substituído; `restarts` subindo sozinho significa
que algo está matando worker. Sem cluster, `enabled` é `false` e o processo se
descreve como worker `0`.

No `/metrics`:

| Métrica | O que mostra |
| --- | --- |
| `sharescreen_cluster_workers_online` / `_configured` | Quantos estão atendendo vs. quantos foram pedidos |
| `sharescreen_cluster_worker_restarts` | Substituições desde que o primário subiu |
| `sharescreen_cluster_worker_up{worker,pid}` | `1` enquanto o worker atende, `0` enquanto ainda está subindo |
| `sharescreen_cluster_worker_uptime_seconds{worker}` | Há quanto tempo cada um está de pé — uptime que zera sozinho é worker que morre |
| `sharescreen_worker_connected_sockets{worker}` | Conexões por worker que realmente as termina. **Soma** para `sharescreen_connected_sockets`, então um split torto salta aos olhos |
| `sharescreen_worker_registered_peers{worker}` | Idem, só os que já registraram nome. Soma para `sharescreen_registered_peers` |

Todas agregadas com `first`, pelo mesmo motivo dos gauges de sala: cada worker
já conhece o cluster inteiro, então somar entre workers reportaria N vezes o
mesmo número.

## Redis

Todos os stores que usam Redis (chat, salas, contas, aviso, parceiros,
apoiadores, pontos de convidado) compartilham **uma** conexão por processo —
`server/redisClient.ts`. Antes cada um abria a sua, o que dava sete conexões
por processo e, com o cluster ligado, sete vezes o número de workers.

| Variável | Para quê |
| --- | --- |
| `REDIS_URL` | Endpoint. Sem ela, cada store volta ao arquivo JSON em disco, como sempre foi |
| `REDIS_CA_CERT` | Certificado da CA, para um endpoint `rediss://` cujo certificado não é de uma CA pública. É o que resolve o `self-signed certificate`. Pode estar em uma linha só ou com `
` escapado — o PEM é remontado antes de ir para o TLS |
| `REDIS_TLS_REJECT_UNAUTHORIZED` | `false` desliga a verificação do certificado. Saída de emergência: a conexão continua cifrada, mas deixa de ser autenticada (ou seja, interceptável). O conserto de verdade é o `REDIS_CA_CERT` |

Erros de conexão são registrados na primeira vez e depois no máximo uma vez
por minuto, com quantas tentativas foram engolidas no intervalo — o
node-redis reconecta sozinho para sempre e emitia um erro por tentativa, o
que com vários workers enchia o console.

## Login com Discord / Google

O fluxo OAuth roda inteiro nesta API (`server/oauthRoutes.ts`) e termina no
mesmo JWT que `/auth/login` já emitia — o front só recebe o token e guarda.
Sem as variáveis abaixo, nada muda: o provedor some da lista e o botão nem
aparece no front.

| Variável | Para quê |
| --- | --- |
| `DISCORD_CLIENT_ID` / `DISCORD_CLIENT_SECRET` | Habilita o botão do Discord |
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` | Habilita o botão do Google |
| `WEB_ORIGINS` | Origens do front que podem receber o token, separadas por vírgula (padrão: `http://localhost:3000`). É a allowlist que impede o callback de virar open redirect |
| `OAUTH_CALLBACK_BASE` | URL pública **desta** API, usada para montar o `redirect_uri`. Sem ela, é derivada do request — bom em dev, mas fixe em produção |

Exemplo de produção:

```
WEB_ORIGINS=https://golive.nemtudo.me
OAUTH_CALLBACK_BASE=https://apigolive.nemtudo.me
```

### Redirect URIs para cadastrar no provedor

- Discord (Developer Portal → OAuth2 → Redirects):
  `https://apigolive.nemtudo.me/auth/oauth/discord/callback`
- Google (Cloud Console → Credenciais → URIs de redirecionamento autorizados):
  `https://apigolive.nemtudo.me/auth/oauth/google/callback`

Em dev, os mesmos caminhos com `http://localhost:4000`.

### Como o fluxo se comporta

- **Já entrou com esse provedor antes:** entra direto na conta de sempre — o
  vínculo é pelo id do provedor, então trocar o e-mail lá fora não muda nada
  aqui.
- **Primeira vez, e o e-mail já é de uma conta daqui:** vincula os dois, mas
  só quando o provedor afirma que o e-mail é verificado. Sem isso, qualquer
  um criaria uma conta descartável com o seu e-mail e entraria na sua.
- **Primeira vez, conta nova:** o usuário escolhe usuário/nome de exibição
  (já pré-preenchidos com o nome do provedor). Nenhuma conta é criada antes
  disso — desistir no meio não deixa lixo no banco.
- **Já tem conta e quer vincular:** estando logado, o front manda o token da
  sessão no `/start` e a API prende o provedor **àquela** conta — mesmo id,
  mesmos flags, mesmo histórico. Se aquela conta do Discord/Google já for o
  acesso de outro usuário daqui, o vínculo é recusado (`identity_taken`) em
  vez de mudar de dono.

Contas criadas por login social ficam sem senha, então não entram por
`/auth/login`. `GET /auth/me` devolve `connections` (`providers` e
`hasPassword`), que é o que alimenta o painel "Conexões" na home, e
`DELETE /auth/oauth/:provider/link` desvincula um provedor — recusando
quando é o último jeito de entrar na conta.
