# Ficha do Pet · Pet Sitter Veterinário

Formulário online para os tutores preencherem a ficha de cuidados do pet antes do serviço de pet sitter, feito para ser usado no celular.

A ficha é salva no Supabase e depois enviada pelo WhatsApp para a veterinária.

## Arquivos

| Arquivo | O que é |
|---|---|
| `index.html` | O formulário inteiro (HTML, CSS e JavaScript, sem dependências) |
| `logo.jpg` | Logo exibida no topo |
| `supabase/01_ficha_pet_seguranca.sql` | Tabela, validação e regras de segurança do banco |

## Configuração

1. No Supabase, abra **SQL Editor**, cole `supabase/01_ficha_pet_seguranca.sql` e clique em **Run**.
2. Em `index.html`, as constantes no início do script:
   - `WA`: WhatsApp da veterinária (DDI + DDD + número, só dígitos).
   - `SB_URL` e `SB_KEY`: URL do projeto e a chave **publishable** do Supabase.

Nunca coloque a chave `service_role` / secret nem a senha do banco no `index.html`. O site é público e qualquer pessoa pode ler o código.

## Segurança

- A tabela `fichas_pet` tem RLS ativo e nenhuma permissão para a chave pública. Pelo site, ninguém consegue listar, ler, editar ou apagar fichas.
- A única entrada é a função `enviar_ficha`, que valida cada campo no servidor (tamanho, formato e opções permitidas) e grava uma ficha.
- Anti-spam: limite de envios por IP (guardado apenas como hash), teto geral por hora, campo invisível contra robôs e tempo mínimo de preenchimento.
- As fichas são lidas pelas veterinárias no painel do Supabase (Table Editor).
- Se o salvamento falhar, a ficha continua sendo enviada pelo WhatsApp.
