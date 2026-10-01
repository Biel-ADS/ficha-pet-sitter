-- =====================================================================
-- AUDITORIA READ-ONLY (so le catalogos do Postgres; nao altera nada)
-- Rode no Supabase: SQL Editor > New query > cole tudo > Run.
-- O resultado e UMA tabela. Procure linhas com ok = false (e leia as "revisar").
-- Nenhum valor secreto e exibido (o salt so aparece como contagem).
-- =====================================================================
with anon_funcs as (
  select p.oid, n.nspname, p.proname, p.prosecdef, p.proconfig,
         has_function_privilege('anon', p.oid, 'execute') as anon_exec,
         has_function_privilege('authenticated', p.oid, 'execute') as auth_exec
  from pg_proc p
  join pg_namespace n on n.oid = p.pronamespace
  where n.nspname in ('public', 'private')
    and not exists (select 1 from pg_depend d where d.objid = p.oid and d.deptype = 'e')
)
select * from (

  -- 1) RLS em TODAS as tabelas do schema public
  select '1 RLS' as secao, 'public.' || c.relname as item,
         case when c.relrowsecurity then 'RLS ligado' else 'RLS DESLIGADO' end as detalhe,
         c.relrowsecurity as ok
  from pg_class c join pg_namespace n on n.oid = c.relnamespace
  where n.nspname = 'public' and c.relkind in ('r', 'p')

  union all
  -- 2) Policies existentes em public (fichas_pet nao pode ter nenhuma)
  select '2 Policies', p.tablename || ' / ' || p.policyname,
         p.cmd || ' para ' || array_to_string(p.roles, ','),
         case when p.tablename = 'fichas_pet' then false else null end
  from pg_policies p where p.schemaname = 'public'

  union all
  -- 3) Privilegios de anon/authenticated/public sobre fichas_pet (todos devem ser false)
  select '3 Grants fichas_pet', r.role || ' ' || pr.priv,
         case when has_table_privilege(r.role, 'public.fichas_pet', pr.priv) then 'TEM' else 'bloqueado' end,
         not has_table_privilege(r.role, 'public.fichas_pet', pr.priv)
  from (values ('anon'), ('authenticated')) as r(role)
  cross join (values ('SELECT'), ('INSERT'), ('UPDATE'), ('DELETE'), ('TRUNCATE'), ('REFERENCES'), ('TRIGGER')) as pr(priv)

  union all
  select '3 Grants fichas_pet', 'PUBLIC (grant para qualquer papel)',
         case when exists (select 1 from pg_class c, aclexplode(c.relacl) a
                           where c.oid = 'public.fichas_pet'::regclass and a.grantee = 0)
              then 'TEM grant para PUBLIC' else 'sem grant para PUBLIC' end,
         not exists (select 1 from pg_class c, aclexplode(c.relacl) a
                     where c.oid = 'public.fichas_pet'::regclass and a.grantee = 0)

  union all
  -- 4) Objetos privados deste projeto: anon nao pode tocar
  select '4 Private', 'private.' || t.n,
         case when has_table_privilege('anon', 'private.' || t.n, 'SELECT,INSERT,UPDATE,DELETE') then 'anon TEM acesso' else 'anon sem acesso' end,
         not has_table_privilege('anon', 'private.' || t.n, 'SELECT,INSERT,UPDATE,DELETE')
  from (values ('envios_log'), ('ficha_segredo')) as t(n)

  union all
  select '4 Private', 'private.ficha_segredo linhas (deve ser 1)', (select count(*)::text from private.ficha_segredo),
         (select count(*) = 1 from private.ficha_segredo)

  union all
  select '4 Private', 'private.ficha_segredo tamanho do salt (>= 32)', (select char_length(salt)::text from private.ficha_segredo limit 1),
         coalesce((select char_length(salt) >= 32 from private.ficha_segredo limit 1), false)

  union all
  -- 5) Funcoes EXECUTE por anon: so enviar_ficha pode aparecer. Outras = revisar (podem ser de outro sistema)
  select '5 Funcoes', f.nspname || '.' || f.proname,
         'anon_exec=' || f.anon_exec || ' authenticated_exec=' || f.auth_exec || ' security_definer=' || f.prosecdef,
         case when f.nspname = 'public' and f.proname = 'enviar_ficha' then f.anon_exec and not f.auth_exec
              when f.proname in ('txt', 'opt', 'multi', 'tel', 'dt') and f.nspname = 'private' then not f.anon_exec and not f.auth_exec
              else null end
  from anon_funcs f
  where f.anon_exec or f.auth_exec or f.nspname = 'private' or f.proname = 'enviar_ficha'

  union all
  -- 6) Toda funcao SECURITY DEFINER precisa de search_path fixo (anti-hijack)
  select '6 search_path', f.nspname || '.' || f.proname,
         coalesce(array_to_string(f.proconfig, ','), 'SEM search_path'),
         coalesce(exists (select 1 from unnest(f.proconfig) c where c like 'search_path=%'), false)
  from anon_funcs f where f.prosecdef

  union all
  -- 7) Views em public (view de dono ignora RLS: precisa security_invoker ou nao ser legivel por anon)
  select '7 Views', 'public.' || c.relname,
         'anon_select=' || has_table_privilege('anon', c.oid, 'SELECT') || ' opcoes=' || coalesce(array_to_string(c.reloptions, ','), '-'),
         (not has_table_privilege('anon', c.oid, 'SELECT')) or coalesce('security_invoker=true' = any(c.reloptions), false)
  from pg_class c join pg_namespace n on n.oid = c.relnamespace
  where n.nspname = 'public' and c.relkind in ('v', 'm')

  union all
  -- 8) Triggers em fichas_pet
  select '8 Triggers', t.tgname, 'em fichas_pet', null
  from pg_trigger t where t.tgrelid = 'public.fichas_pet'::regclass and not t.tgisinternal

  union all
  -- 9) Storage: nenhum bucket publico sem necessidade
  select '9 Storage', 'bucket ' || b.name, case when b.public then 'PUBLICO' else 'privado' end, not b.public
  from storage.buckets b

  union all
  -- 10) Schemas expostos pela Data API: "private" NAO pode estar na lista
  select '10 Data API', 'schemas expostos', coalesce(string_agg(c, ' | '), '(config padrao: public)'),
         coalesce(bool_and(c not like '%private%'), true)
  from (select unnest(rolconfig) as c from pg_roles where rolname = 'authenticator') s
  where c like 'pgrst.db_schemas%'

  union all
  -- 11) Estrutura esperada da migracao
  select '11 Estrutura', 'fichas_pet.sig_hash existe',
         exists (select 1 from information_schema.columns where table_schema = 'public' and table_name = 'fichas_pet' and column_name = 'sig_hash')::text,
         exists (select 1 from information_schema.columns where table_schema = 'public' and table_name = 'fichas_pet' and column_name = 'sig_hash')

  union all
  select '11 Estrutura', 'indice unico fichas_pet_sig_hash_uq', '',
         exists (select 1 from pg_indexes where schemaname = 'public' and indexname = 'fichas_pet_sig_hash_uq')

  union all
  select '11 Estrutura', 'constraint fichas_pet_desp (despesas obrigatorio)', '',
         exists (select 1 from pg_constraint where conname = 'fichas_pet_desp')

) r
order by 1, 2;
