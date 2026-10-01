-- =====================================================================
-- TESTES DE SEGURANCA (simulam a chave publica "anon" chamando a API)
-- Rode no Supabase: SQL Editor > New query > cole tudo > Run.
--
-- SEGURO PARA PRODUCAO: tudo roda dentro de um bloco que, no FIM, levanta um
-- erro de proposito. Isso DESFAZ tudo (fichas de teste e contadores de rate limit).
-- Nenhuma ficha real e lida, alterada ou apagada. O "erro" vermelho no final E o
-- relatorio: leia as linhas [OK] / [FALHA].
-- =====================================================================
do $$
declare
  out text := '';
  b jsonb;            -- payload valido base
  cases jsonb;
  c record;
  r jsonb;
  got text;
  n int;
  k int;
  png constant text := 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAAB';  -- cabecalho PNG valido (32 chars base64)
  hdr text;
begin
  b := jsonb_build_object(
    'nome','TESTE-AUDITORIA Silva','tel','(77) 91234-5678','tel2','(77) 91234-5679','end','Rua dos Testes 123',
    'pet','Rex','esp','Cão','sexo','Macho','cast','Sim','vac','Sim','doe','Não','med','Não','autvet','Sim',
    'ali','Mista','pess','Sim','anim','Sim','foge','Não','agr','Não',
    'ini', to_char(current_date,'YYYY-MM-DD'), 'fim', to_char(current_date + 3,'YYYY-MM-DD'),
    'acesso','Chave comigo','aut','Autorizo','desp',true,'_ms',30000,'site','',
    'animais',2,'dias',5,'valor',280);

  -- ---------- A) acesso direto a tabelas/funcoes como anon (tudo deve ser bloqueado) ----------
  foreach hdr in array array[
    'select 1 from public.fichas_pet limit 1',
    'insert into public.fichas_pet (nome) values (''x'')',
    'update public.fichas_pet set nome = ''x''',
    'delete from public.fichas_pet',
    'select 1 from private.envios_log limit 1',
    'select 1 from private.ficha_segredo limit 1',
    'select private.txt(''{}''::jsonb, ''a'', 5)',
    'select private.tel(''{}''::jsonb, ''a'', false)',
    'select private.preco_plano(1, 1)'
  ] loop
    begin
      set local role anon;
      execute hdr;
      got := 'PERMITIDO';
    exception when insufficient_privilege then got := 'bloqueado';
              when others then got := 'erro: ' || sqlstate;
    end;
    reset role;
    out := out || format(E'%s | anon: %s -> %s\n', case when got = 'bloqueado' then '[OK]' else '[FALHA]' end, hdr, got);
  end loop;

  -- ---------- B) envio valido, resposta minima, replay ----------
  perform set_config('request.headers', '{"cf-connecting-ip":"198.51.100.1"}', true);
  begin
    set local role anon;
    r := public.enviar_ficha(b || jsonb_build_object('sig', png || 'AA01'));
    got := case when r = '{"ok": true}'::jsonb then 'ok' else 'RESPOSTA INESPERADA: ' || r::text end;
  exception when others then got := sqlerrm;
  end;
  reset role;
  out := out || format(E'%s | envio valido (resposta so {"ok":true}) -> %s\n', case when got = 'ok' then '[OK]' else '[FALHA]' end, got);

  begin  -- mesma requisicao de novo (retry / replay / clique duplo)
    set local role anon;
    r := public.enviar_ficha(b || jsonb_build_object('sig', png || 'AA01'));
    got := 'ok';
  exception when others then got := sqlerrm;
  end;
  reset role;
  select count(*) into n from public.fichas_pet where nome = 'TESTE-AUDITORIA Silva';
  out := out || format(E'%s | replay da mesma ficha: resposta=%s, fichas gravadas=%s (esperado 1)\n',
                       case when got = 'ok' and n = 1 then '[OK]' else '[FALHA]' end, got, n);

  -- ---------- C) payloads adulterados (cada um deve ser rejeitado com o motivo certo) ----------
  cases := jsonb_build_array(
    jsonb_build_object('t','campo extra inesperado','e','invalido:payload','p', b || jsonb_build_object('admin',true,'sig',png||'AA02')),
    jsonb_build_object('t','campo extra id','e','invalido:payload','p', b || jsonb_build_object('id','00000000-0000-0000-0000-000000000000','sig',png||'AA03')),
    jsonb_build_object('t','nome ausente','e','obrigatorio:nome','p', (b - 'nome') || jsonb_build_object('sig',png||'AA04')),
    jsonb_build_object('t','nome com tipo errado (numero)','e','invalido:nome','p', b || jsonb_build_object('nome',123,'sig',png||'AA05')),
    jsonb_build_object('t','nome gigante (121 chars)','e','tamanho:nome','p', b || jsonb_build_object('nome',repeat('a',121),'sig',png||'AA06')),
    jsonb_build_object('t','medo como texto (nao array)','e','invalido:medo','p', b || jsonb_build_object('medo','Fogos','sig',png||'AA07')),
    jsonb_build_object('t','medo com valor fora da lista','e','invalido:medo','p', b || jsonb_build_object('medo',jsonb_build_array('<script>'),'sig',png||'AA08')),
    jsonb_build_object('t','medo "Nada" + outro','e','invalido:medo','p', b || jsonb_build_object('medo',jsonb_build_array('Nada','Fogos'),'sig',png||'AA09')),
    jsonb_build_object('t','data inexistente 2026-02-31','e','formato:ini','p', b || jsonb_build_object('ini','2026-02-31','sig',png||'AA10')),
    jsonb_build_object('t','data de termino antes do inicio','e','intervalo:fim','p', b || jsonb_build_object('fim', to_char(current_date - 1,'YYYY-MM-DD'),'sig',png||'AA11')),
    jsonb_build_object('t','telefone invalido','e','formato:tel','p', b || jsonb_build_object('tel','123','sig',png||'AA12')),
    jsonb_build_object('t','opcao fora da lista (esp)','e','invalido:esp','p', b || jsonb_build_object('esp','Dragao','sig',png||'AA13')),
    jsonb_build_object('t','assinatura que nao e PNG','e','invalido:sig','p', b || jsonb_build_object('sig','data:image/png;base64,AAAA')),
    jsonb_build_object('t','assinatura com HTML','e','invalido:sig','p', b || jsonb_build_object('sig','data:image/svg+xml;base64,PHN2Zz48L3N2Zz4=')),
    jsonb_build_object('t','assinatura ausente','e','obrigatorio:sig','p', b),
    jsonb_build_object('t','JSON excessivamente grande (>250 KB)','e','invalido:payload','p', b || jsonb_build_object('hab',repeat('x',260000),'sig',png||'AA14')),
    jsonb_build_object('t','payload nao e objeto','e','invalido:payload','p', '[1,2,3]'::jsonb),
    jsonb_build_object('t','sem aceite de despesas','e','obrigatorio:desp','p', b || jsonb_build_object('desp',false,'sig',png||'AA15')),
    jsonb_build_object('t','preenchimento rapido (_ms=1000)','e','rapido:payload','p', b || jsonb_build_object('_ms',1000,'sig',png||'AA16')),
    jsonb_build_object('t','sem _ms','e','rapido:payload','p', (b - '_ms') || jsonb_build_object('sig',png||'AA17')),
    jsonb_build_object('t','PRECO ADULTERADO: 2 animais + 5 dias com valor 1','e','invalido:valor','p', b || jsonb_build_object('valor',1,'sig',png||'AA19')),
    jsonb_build_object('t','PRECO ADULTERADO: valor 280 para 1 animal + 1 dia','e','invalido:valor','p', b || jsonb_build_object('animais',1,'dias',1,'valor',280,'sig',png||'AA20')),
    jsonb_build_object('t','valor como texto "280"','e','invalido:valor','p', b || jsonb_build_object('valor','280','sig',png||'AA21')),
    jsonb_build_object('t','animais fora da faixa (5)','e','invalido:animais','p', b || jsonb_build_object('animais',5,'sig',png||'AA22')),
    jsonb_build_object('t','animais como texto "2"','e','invalido:animais','p', b || jsonb_build_object('animais','2','sig',png||'AA23')),
    jsonb_build_object('t','dias fora da faixa (8)','e','invalido:dias','p', b || jsonb_build_object('dias',8,'sig',png||'AA24')),
    jsonb_build_object('t','dias decimal (2.5)','e','invalido:dias','p', b || jsonb_build_object('dias',2.5,'sig',png||'AA25')),
    jsonb_build_object('t','valor sem animais/dias','e','invalido:animais','p', (b - 'animais' - 'dias') || jsonb_build_object('sig',png||'AA26')),
    jsonb_build_object('t','sem plano nenhum (pagina antiga ainda aberta) continua salvando','e','ok','p', (b - 'animais' - 'dias' - 'valor') || jsonb_build_object('nome','TESTE-AUDITORIA Antigo','sig',png||'AA27')),
    jsonb_build_object('t','honeypot preenchido (finge sucesso, nao grava)','e','ok','p', b || jsonb_build_object('site','bot','nome','TESTE-AUDITORIA Bot','sig',png||'AA18'))
  );
  k := 0;
  for c in select e.x from jsonb_array_elements(cases) as e(x) loop
    k := k + 1;
    perform set_config('request.headers', jsonb_build_object('cf-connecting-ip', '198.51.100.' || (10 + k))::text, true);
    begin
      set local role anon;
      r := public.enviar_ficha(c.x->'p');
      got := case when r = '{"ok": true}'::jsonb then 'ok' else r::text end;
    exception when others then got := sqlerrm;
    end;
    reset role;
    out := out || format(E'%s | %s -> esperado=%s obtido=%s\n',
                         case when got = c.x->>'e' then '[OK]' else '[FALHA]' end, c.x->>'t', c.x->>'e', got);
  end loop;
  select count(*) into n from public.fichas_pet where nome = 'TESTE-AUDITORIA Bot';
  out := out || format(E'%s | honeypot nao gravou nada: fichas=%s (esperado 0)\n', case when n = 0 then '[OK]' else '[FALHA]' end, n);

  -- ---------- C2) plano: o valor GRAVADO vem da tabela do servidor ----------
  k := 0;
  for c in select e.x from jsonb_array_elements('[[1,1,50],[1,7,290],[2,5,280],[3,6,395],[4,7,530]]'::jsonb) as e(x) loop
    k := k + 1;
    perform set_config('request.headers', jsonb_build_object('cf-connecting-ip', '198.51.100.' || (150 + k))::text, true);
    begin
      set local role anon;
      r := public.enviar_ficha(b || jsonb_build_object('nome','TESTE-AUDITORIA Plano ' || k,
             'animais',(c.x->>0)::int,'dias',(c.x->>1)::int,'valor',(c.x->>2)::int,'sig',png || 'CC' || lpad(k::text,2,'0')));
      got := 'ok';
    exception when others then got := sqlerrm;
    end;
    reset role;
    select count(*) into n from public.fichas_pet
      where nome = 'TESTE-AUDITORIA Plano ' || k and animais = (c.x->>0)::int and dias = (c.x->>1)::int and valor = (c.x->>2)::int;
    out := out || format(E'%s | gravou %s animal(is) + %s dia(s) = R$%s (resposta=%s, linhas corretas=%s)
',
                         case when got = 'ok' and n = 1 then '[OK]' else '[FALHA]' end, c.x->>0, c.x->>1, c.x->>2, got, n);
  end loop;
  select count(*) into n from public.fichas_pet where nome like 'TESTE-AUDITORIA%' and valor is not null and valor not in (50,290,280,395,530);
  out := out || format(E'%s | nenhuma ficha de teste gravada com preco fora do esperado: %s
', case when n = 0 then '[OK]' else '[FALHA]' end, n);
  select string_agg(private.preco_plano(a, d)::text, ',' order by a, d) into got
    from generate_series(1,4) a, generate_series(1,7) d;
  out := out || format(E'%s | tabela do servidor tem os 28 precos oficiais
',
    case when got = '50,100,140,180,220,255,290,65,130,180,230,280,325,370,80,160,220,280,340,395,450,95,190,260,330,400,465,530' then '[OK]' else '[FALHA] ' || got end);
  select count(*) into n from public.fichas_pet where nome in ('TESTE-AUDITORIA Silva') and valor = 280;
  out := out || format(E'%s | envio valido grava valor 280 (calculado pelo servidor): %s linha(s)
', case when n = 1 then '[OK]' else '[FALHA]' end, n);

  -- ---------- D) rate limit: 3 por 10 min por IP; o 4o deve dar "limite" ----------
  perform set_config('request.headers', '{"cf-connecting-ip":"198.51.100.200"}', true);
  for k in 1..4 loop
    begin
      set local role anon;
      r := public.enviar_ficha(b || jsonb_build_object('nome','TESTE-AUDITORIA RL','sig', png || 'BB' || lpad(k::text, 2, '0')));
      got := 'ok';
    exception when others then got := sqlerrm;
    end;
    reset role;
    out := out || format(E'%s | rate limit, mesmo IP, envio %s -> %s (esperado %s)\n',
                         case when got = case when k <= 3 then 'ok' else 'limite:payload' end then '[OK]' else '[FALHA]' end,
                         k, got, case when k <= 3 then 'ok' else 'limite:payload' end);
  end loop;
  perform set_config('request.headers', '{"cf-connecting-ip":"198.51.100.201"}', true);  -- outro IP nao e afetado
  begin
    set local role anon;
    r := public.enviar_ficha(b || jsonb_build_object('nome','TESTE-AUDITORIA RL2','sig', png || 'BB99'));
    got := 'ok';
  exception when others then got := sqlerrm;
  end;
  reset role;
  out := out || format(E'%s | rate limit: outro IP continua aceito -> %s\n', case when got = 'ok' then '[OK]' else '[FALHA]' end, got);

  -- ---------- E) tamanho do teto global (informativo) ----------
  select count(*) into n from private.envios_log where created_at > now() - interval '1 hour';
  out := out || format(E'[INFO] envios na ultima hora (inclui os de teste; teto global = 60): %s\n', n);

  -- Desfaz TUDO (fichas de teste, log de rate limit). O erro abaixo e o relatorio.
  raise exception E'\n===== RELATORIO (nada foi gravado; transacao desfeita) =====\n%', out;
end $$;
