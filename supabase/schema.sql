create table if not exists public.applications (
  id text primary key,
  submitted_at timestamptz not null,
  data_json jsonb not null,
  id_image_path text not null,
  license_image_path text
);

create index if not exists applications_submitted_at_idx
  on public.applications (submitted_at desc, id desc);

create table if not exists public.sessions (
  token_hash text primary key,
  expires_at timestamptz not null
);

create index if not exists sessions_expires_at_idx on public.sessions (expires_at);

alter table public.applications enable row level security;
alter table public.sessions enable row level security;
revoke all on public.applications, public.sessions from anon, authenticated;
grant all on public.applications, public.sessions to service_role;

insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values (
  'driver-documents', 'driver-documents', false, 4194304,
  array['image/jpeg', 'image/png', 'image/gif', 'image/webp', 'image/heic', 'application/pdf']
)
on conflict (id) do update set
  public = false,
  file_size_limit = excluded.file_size_limit,
  allowed_mime_types = excluded.allowed_mime_types;
