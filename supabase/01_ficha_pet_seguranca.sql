-- =====================================================================
-- Ficha do Pet: tabela + segurança (least privilege)
-- Run the whole file ONCE in Supabase: Dashboard > SQL Editor > New query > Run.
-- Safe to re-run: it recreates the functions and permissions.
--
-- Security model:
--   * public.fichas_pet: RLS ON, ZERO policies, no grants to anon/authenticated.
--     The public (publishable) key cannot SELECT/INSERT/UPDATE/DELETE on it at all.
--   * The only public entry point is the function public.enviar_ficha(payload),
--     SECURITY DEFINER, which validates/sanitizes every field, rate-limits
--     by IP hash and inserts ONE row. It returns nothing about other rows.
--   * Helpers and the rate-limit log live in schema "private", which the
--     Data API does not expose.
--   * The vets read the forms in the Dashboard (Table Editor), which uses an
--     admin role and is not affected by RLS.
-- =====================================================================

create extension if not exists pgcrypto with schema extensions;

-- NOTE: in this project "private" is SHARED with another system whose RLS
-- policies call private.* functions as anon/authenticated. Never revoke
-- schema-wide privileges here; only lock down the objects this file creates.
create schema if not exists private;

-- ---------------------------------------------------------------------
-- Tables
-- ---------------------------------------------------------------------
create table if not exists public.fichas_pet (
  id uuid primary key default gen_random_uuid(),
  created_at timestamptz not null default now(),
  -- tutor
  nome text not null,
  tel text not null,
  tel2 text not null,
  endereco text not null,
  contato_familiar text,
  -- pet
  pet text not null,
  especie text not null,
  raca text,
  idade text,
  sexo text not null,
  castrado text not null,
  peso text,
  -- saúde
  vacinas text not null,
  doenca text not null,
  doenca_qual text,
  medicamentos text not null,
  medicamentos_detalhe text,
  alergias text,
  autoriza_atendimento text not null,
  -- alimentação
  alimentacao text not null,
  quantidade text,
  horarios_refeicao text,
  alimentos_proibidos text,
  -- comportamento
  sociavel_pessoas text not null,
  sociavel_animais text not null,
  medos text[],
  medo_outros text,
  foge text not null,
  agressivo text not null,
  habitos text,
  -- rotina
  data_inicio date not null,
  data_fim date not null,
  horarios text,
  servicos text[],
  -- casa
  acesso text not null,
  instrucoes text,
  -- termo
  autoriza_decisoes text not null,
  responsavel_despesas boolean not null,
  data_termo date not null,
  assinatura_png text not null,
  -- abuse control (sha256 of the IP, never the raw IP)
  ip_hash text not null,
  -- backstop limits (the function validates first; these catch anything else)
  constraint fichas_pet_datas check (data_fim >= data_inicio),
  constraint fichas_pet_desp check (responsavel_despesas),
  constraint fichas_pet_assinatura check (
    assinatura_png like 'data:image/png;base64,%' and octet_length(assinatura_png) <= 200000),
  constraint fichas_pet_tamanhos check (
    char_length(nome) <= 120 and char_length(tel) <= 20 and char_length(tel2) <= 20
    and char_length(endereco) <= 200 and char_length(coalesce(contato_familiar,'')) <= 160
    and char_length(pet) <= 60 and char_length(coalesce(raca,'')) <= 60
    and char_length(coalesce(idade,'')) <= 30 and char_length(coalesce(peso,'')) <= 10
    and char_length(coalesce(doenca_qual,'')) <= 500 and char_length(coalesce(medicamentos_detalhe,'')) <= 500
    and char_length(coalesce(alergias,'')) <= 200 and char_length(coalesce(quantidade,'')) <= 80
    and char_length(coalesce(horarios_refeicao,'')) <= 80 and char_length(coalesce(alimentos_proibidos,'')) <= 200
    and char_length(coalesce(medo_outros,'')) <= 120 and char_length(coalesce(habitos,'')) <= 800
    and char_length(coalesce(horarios,'')) <= 80 and char_length(coalesce(instrucoes,'')) <= 600)
);

-- Added later: text typed when "Outro" is chosen (adds the columns to the existing table)
alter table public.fichas_pet add column if not exists especie_outra text
  constraint fichas_pet_especie_outra check (char_length(especie_outra) <= 60);
alter table public.fichas_pet add column if not exists acesso_outro text
  constraint fichas_pet_acesso_outro check (char_length(acesso_outro) <= 120);

-- Hardening: signature hash makes the same submission idempotent (double click, retry,
-- replayed request) without touching existing rows (NULL for old rows, partial unique index).
alter table public.fichas_pet add column if not exists sig_hash text;
create unique index if not exists fichas_pet_sig_hash_uq on public.fichas_pet (sig_hash) where sig_hash is not null;

-- Secret salt for the IP hash: a bare sha256(IP) can be reversed by brute force (only ~4 billion IPv4).
-- The salt is random, generated once here, and never leaves the database.
create table if not exists private.ficha_segredo (
  id boolean primary key default true check (id),
  salt text not null default encode(extensions.gen_random_bytes(32), 'hex')
);
insert into private.ficha_segredo (id) values (true) on conflict do nothing;
alter table private.ficha_segredo enable row level security;
revoke all on table private.ficha_segredo from public, anon, authenticated;

create table if not exists private.envios_log (
  ip_hash text not null,
  created_at timestamptz not null default now()
);
create index if not exists envios_log_ip_idx on private.envios_log (ip_hash, created_at);
create index if not exists envios_log_time_idx on private.envios_log (created_at);

-- ---------------------------------------------------------------------
-- Lock down: RLS on, no policies, no table grants for API roles
-- ---------------------------------------------------------------------
alter table public.fichas_pet enable row level security;
alter table private.envios_log enable row level security;
revoke all on table public.fichas_pet from public, anon, authenticated;
revoke all on table private.envios_log from public, anon, authenticated;
-- Drop any policy that may have been created by hand on the table
do $$ declare p record; begin
  for p in select policyname from pg_policies where schemaname = 'public' and tablename = 'fichas_pet' loop
    execute format('drop policy %I on public.fichas_pet', p.policyname);
  end loop;
end $$;

-- ---------------------------------------------------------------------
-- Validation helpers (private, not callable through the API)
-- Errors are raised as "<motivo>:<campo>" so the form can point to the field.
-- ---------------------------------------------------------------------
create or replace function private.txt(p jsonb, k text, maxlen int, req boolean default false,
                                       multiline boolean default false, minlen int default 1)
returns text language plpgsql immutable set search_path = '' as $$
declare v text;
begin
  if p ? k and jsonb_typeof(p->k) not in ('string', 'null') then
    raise exception using errcode = '22023', message = 'invalido:' || k;
  end if;
  v := coalesce(p->>k, '');
  -- strip control characters; single-line fields also lose line breaks/tabs
  v := regexp_replace(v, '[\x01-\x08\x0B\x0C\x0E-\x1F\x7F]', '', 'g');
  if not multiline then v := regexp_replace(v, '[\r\n\t]+', ' ', 'g'); end if;
  v := nullif(btrim(v), '');
  if v is null then
    if req then raise exception using errcode = '22023', message = 'obrigatorio:' || k; end if;
    return null;
  end if;
  if char_length(v) < minlen or char_length(v) > maxlen then
    raise exception using errcode = '22023', message = 'tamanho:' || k;
  end if;
  return v;
end $$;

create or replace function private.opt(p jsonb, k text, opts text[], req boolean)
returns text language plpgsql immutable set search_path = '' as $$
declare v text := private.txt(p, k, 60, req);
begin
  if v is not null and not (v = any(opts)) then
    raise exception using errcode = '22023', message = 'invalido:' || k;
  end if;
  return v;
end $$;

create or replace function private.multi(p jsonb, k text, opts text[])
returns text[] language plpgsql immutable set search_path = '' as $$
declare a text[];
begin
  if not (p ? k) or jsonb_typeof(p->k) = 'null' then return null; end if;
  if jsonb_typeof(p->k) <> 'array' or jsonb_array_length(p->k) > cardinality(opts) then
    raise exception using errcode = '22023', message = 'invalido:' || k;
  end if;
  select array_agg(distinct x) into a from jsonb_array_elements_text(p->k) as x;
  if a is not null and exists (select 1 from unnest(a) as x where not (x = any(opts))) then
    raise exception using errcode = '22023', message = 'invalido:' || k;
  end if;
  return a;
end $$;

create or replace function private.tel(p jsonb, k text, req boolean)
returns text language plpgsql immutable set search_path = '' as $$
declare v text := private.txt(p, k, 20, req);
begin
  if v is null then return null; end if;
  if v !~ '^[0-9()+ .-]+$' or char_length(regexp_replace(v, '\D', '', 'g')) not between 10 and 13 then
    raise exception using errcode = '22023', message = 'formato:' || k;
  end if;
  return v;
end $$;

create or replace function private.dt(p jsonb, k text, req boolean)
returns date language plpgsql immutable set search_path = '' as $$
declare v text := private.txt(p, k, 10, req);
begin
  if v is null then return null; end if;
  if v !~ '^\d{4}-\d{2}-\d{2}$' then
    raise exception using errcode = '22023', message = 'formato:' || k;
  end if;
  begin
    return v::date;
  exception when others then
    raise exception using errcode = '22023', message = 'formato:' || k;
  end;
end $$;

-- ---------------------------------------------------------------------
-- Public entry point
-- ---------------------------------------------------------------------
create or replace function public.enviar_ficha(payload jsonb)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  y  constant text[] := array['Sim', 'Não'];
  yn constant text[] := array['Sim', 'Não', 'Não sei'];
  soc constant text[] := array['Sim', 'Mais ou menos', 'Não'];
  hdr jsonb;
  ip text;
  h text;
  ms bigint;
  v_doe text; v_med text; v_medos text[];
  v_ini date; v_fim date; v_data date;
  sig text;
  sh text;
  v_salt text;
  -- every key the form may send; anything else is rejected (no mass assignment)
  allowed constant text[] := array[
    'nome','tel','tel2','end','fam','pet','esp','espq','raca','idade','sexo','cast','peso',
    'vac','doe','doeq','med','medq','ale','autvet','ali','qtd','hor','proib',
    'pess','anim','medo','medoq','foge','agr','hab','ini','fim','hora','serv',
    'acesso','acessoq','inst','aut','desp','data','sig','site','_ms'];
begin
  -- 1) envelope
  if payload is null or jsonb_typeof(payload) <> 'object' or octet_length(payload::text) > 250000 then
    raise exception using errcode = '22023', message = 'invalido:payload';
  end if;
  if exists (select 1 from jsonb_object_keys(payload) as k where k <> all(allowed)) then
    raise exception using errcode = '22023', message = 'invalido:payload';
  end if;

  -- 2) bot traps: honeypot filled => pretend success, store nothing
  if coalesce(payload->>'site', '') <> '' then
    return jsonb_build_object('ok', true);
  end if;
  ms := case when coalesce(payload->>'_ms', '') ~ '^\d{1,10}$' then (payload->>'_ms')::bigint else 0 end;
  if ms < 20000 then  -- nobody fills 8 steps + signature in under 20 s
    raise exception using errcode = 'P0001', message = 'rapido:payload';
  end if;

  -- 3) rate limit per IP hash (+ global ceiling)
  hdr := nullif(current_setting('request.headers', true), '')::jsonb;
  -- cf-connecting-ip is set by Cloudflare in front of Supabase and cannot be forged by the
  -- client; x-forwarded-for can be, so it is only a fallback. The global ceiling below
  -- still caps total volume if an attacker rotates spoofed IPs.
  ip := btrim(split_part(coalesce(hdr->>'cf-connecting-ip', hdr->>'x-real-ip', hdr->>'x-forwarded-for', 'desconhecido'), ',', 1));
  select s.salt into v_salt from private.ficha_segredo s limit 1;
  h := encode(extensions.digest(ip || '|' || coalesce(v_salt, 'ficha-pet'), 'sha256'), 'hex');
  perform pg_advisory_xact_lock(hashtext(h));
  if (select count(*) from private.envios_log where ip_hash = h and created_at > now() - interval '10 minutes') >= 3
     or (select count(*) from private.envios_log where ip_hash = h and created_at > now() - interval '1 day') >= 10
     or (select count(*) from private.envios_log where created_at > now() - interval '1 hour') >= 60 then
    raise exception using errcode = 'P0001', message = 'limite:payload';
  end if;
  delete from private.envios_log where created_at < now() - interval '2 days';

  -- 4) cross-field rules
  v_doe := private.opt(payload, 'doe', y, true);
  v_med := private.opt(payload, 'med', y, true);
  v_medos := private.multi(payload, 'medo', array['Fogos', 'Trovões', 'Pessoas estranhas', 'Barulhos', 'Nada', 'Outros']);
  if v_medos @> array['Nada'] and cardinality(v_medos) > 1 then
    raise exception using errcode = '22023', message = 'invalido:medo';
  end if;

  v_ini := private.dt(payload, 'ini', true);
  v_fim := private.dt(payload, 'fim', true);
  if v_ini < current_date - 730 or v_ini > current_date + 730 then
    raise exception using errcode = '22023', message = 'intervalo:ini';
  end if;
  if v_fim < v_ini or v_fim > v_ini + 365 then
    raise exception using errcode = '22023', message = 'intervalo:fim';
  end if;
  v_data := coalesce(private.dt(payload, 'data', false), current_date);
  if v_data not between current_date - 7 and current_date + 7 then
    raise exception using errcode = '22023', message = 'intervalo:data';
  end if;

  if payload->'desp' is distinct from 'true'::jsonb then
    raise exception using errcode = '22023', message = 'obrigatorio:desp';
  end if;

  -- signature: PNG data URL, <= 200 KB, real PNG bytes
  if jsonb_typeof(payload->'sig') is distinct from 'string' then
    raise exception using errcode = '22023', message = 'obrigatorio:sig';
  end if;
  sig := payload->>'sig';
  if octet_length(sig) > 200000
     or sig !~ '^data:image/png;base64,[A-Za-z0-9+/]+={0,2}$' then
    raise exception using errcode = '22023', message = 'invalido:sig';
  end if;
  begin
    if substring(decode(substring(sig from 23), 'base64') from 1 for 8) <> '\x89504e470d0a1a0a'::bytea then
      raise exception using errcode = '22023', message = 'invalido:sig';
    end if;
  exception when others then
    raise exception using errcode = '22023', message = 'invalido:sig';
  end;

  -- idempotency / replay: the same signature image is never stored twice; a repeat
  -- (double click, retry after a network failure, replayed request) just gets "ok"
  sh := encode(extensions.digest(sig, 'sha256'), 'hex');
  perform pg_advisory_xact_lock(hashtext('sig|' || sh));
  if exists (select 1 from public.fichas_pet where sig_hash = sh) then
    return jsonb_build_object('ok', true);
  end if;

  -- 5) insert exactly one row, only allow-listed fields.
  -- Any unexpected database error is turned into a generic message so table/constraint
  -- names and row contents never reach the client.
  begin
  insert into public.fichas_pet (
    nome, tel, tel2, endereco, contato_familiar,
    pet, especie, raca, idade, sexo, castrado, peso,
    vacinas, doenca, doenca_qual, medicamentos, medicamentos_detalhe, alergias, autoriza_atendimento,
    alimentacao, quantidade, horarios_refeicao, alimentos_proibidos,
    sociavel_pessoas, sociavel_animais, medos, medo_outros, foge, agressivo, habitos,
    data_inicio, data_fim, horarios, servicos,
    acesso, instrucoes,
    especie_outra, acesso_outro,
    autoriza_decisoes, responsavel_despesas, data_termo, assinatura_png, ip_hash, sig_hash
  ) values (
    private.txt(payload, 'nome', 120, true, false, 3),
    private.tel(payload, 'tel', true),
    private.tel(payload, 'tel2', true),
    private.txt(payload, 'end', 200, true, false, 5),
    private.txt(payload, 'fam', 160),
    private.txt(payload, 'pet', 60, true),
    private.opt(payload, 'esp', array['Cão', 'Gato', 'Ave', 'Roedor', 'Outro'], true),
    private.txt(payload, 'raca', 60),
    private.txt(payload, 'idade', 30),
    private.opt(payload, 'sexo', array['Macho', 'Fêmea'], true),
    private.opt(payload, 'cast', y, true),
    private.txt(payload, 'peso', 10),
    private.opt(payload, 'vac', yn, true),
    v_doe,
    case when v_doe = 'Sim' then private.txt(payload, 'doeq', 500, false, true) end,
    v_med,
    case when v_med = 'Sim' then private.txt(payload, 'medq', 500, false, true) end,
    private.txt(payload, 'ale', 200),
    private.opt(payload, 'autvet', y, true),
    private.opt(payload, 'ali', array['Ração seca', 'Ração úmida', 'Natural', 'Mista'], true),
    private.txt(payload, 'qtd', 80),
    private.txt(payload, 'hor', 80),
    private.txt(payload, 'proib', 200),
    private.opt(payload, 'pess', soc, true),
    private.opt(payload, 'anim', soc, true),
    v_medos,
    case when v_medos @> array['Outros'] then private.txt(payload, 'medoq', 120) end,
    private.opt(payload, 'foge', y, true),
    private.opt(payload, 'agr', y, true),
    private.txt(payload, 'hab', 800, false, true),
    v_ini,
    v_fim,
    private.txt(payload, 'hora', 80),
    private.multi(payload, 'serv', array['Alimentação', 'Troca de água', 'Limpeza', 'Passeio', 'Medicação',
                                         'Enriquecimento ambiental', 'Fotos e vídeos']),
    private.opt(payload, 'acesso', array['Chave comigo', 'Portaria', 'Alguém entrega', 'Outro'], true),
    private.txt(payload, 'inst', 600, false, true),
    case when payload->>'esp' = 'Outro' then private.txt(payload, 'espq', 60) end,
    case when payload->>'acesso' = 'Outro' then private.txt(payload, 'acessoq', 120) end,
    private.opt(payload, 'aut', array['Autorizo', 'Não autorizo'], true),
    true,
    v_data,
    sig,
    h,
    sh
  );
  exception
    when unique_violation then
      return jsonb_build_object('ok', true);  -- concurrent duplicate of the same submission
    when check_violation or not_null_violation or string_data_right_truncation
         or invalid_text_representation or datetime_field_overflow then
      raise exception using errcode = '22023', message = 'invalido:payload';
  end;
  insert into private.envios_log (ip_hash) values (h);

  return jsonb_build_object('ok', true);
end $$;

-- ---------------------------------------------------------------------
-- Function permissions: only enviar_ficha is callable, and only by anon
-- ---------------------------------------------------------------------
-- Only this file's helpers; other functions in "private" belong to another system.
revoke execute on function private.txt(jsonb, text, int, boolean, boolean, int) from public, anon, authenticated;
revoke execute on function private.opt(jsonb, text, text[], boolean) from public, anon, authenticated;
revoke execute on function private.multi(jsonb, text, text[]) from public, anon, authenticated;
revoke execute on function private.tel(jsonb, text, boolean) from public, anon, authenticated;
revoke execute on function private.dt(jsonb, text, boolean) from public, anon, authenticated;
revoke execute on function public.enviar_ficha(jsonb) from public, anon, authenticated;
grant execute on function public.enviar_ficha(jsonb) to anon;

-- ---------------------------------------------------------------------
-- Audit (result shown below after Run): RLS status of EVERY table in
-- "public" and any policy that grants access to anon/public.
-- Any row with rls_ativo = false or a policy for anon deserves a look.
-- ---------------------------------------------------------------------
select c.relname as tabela,
       c.relrowsecurity as rls_ativo,
       (select string_agg(p.policyname || ' [' || p.cmd || ' para ' || array_to_string(p.roles, ',') || ']', '; ')
          from pg_policies p where p.schemaname = 'public' and p.tablename = c.relname) as politicas,
       has_table_privilege('anon', c.oid, 'SELECT') as anon_pode_ler,
       has_table_privilege('anon', c.oid, 'INSERT') as anon_pode_inserir
from pg_class c
join pg_namespace n on n.oid = c.relnamespace
where n.nspname = 'public' and c.relkind in ('r', 'p')
order by c.relname;
