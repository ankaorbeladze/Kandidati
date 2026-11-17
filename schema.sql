-- Kandidati — database schema (v1)
-- Run once in Supabase: SQL Editor → New query → paste everything → Run.

-- ============ TABLES ============

create table if not exists public.profiles (
  id          uuid primary key references auth.users(id) on delete cascade,
  role        text not null check (role in ('candidate','employer')),
  full_name   text not null default '',
  phone       text default '',
  city        text default '',
  created_at  timestamptz not null default now()
);

create table if not exists public.candidate_profiles (
  user_id          uuid primary key references public.profiles(id) on delete cascade,
  headline         text default '',
  experience_years int  default 0 check (experience_years between 0 and 60),
  skills           text default '',
  about            text default '',
  cv_path          text,
  updated_at       timestamptz not null default now()
);

create table if not exists public.companies (
  id          uuid primary key default gen_random_uuid(),
  owner_id    uuid not null unique references public.profiles(id) on delete cascade,
  name        text not null,
  industry    text default '',
  city        text default '',
  website     text default '',
  about       text default '',
  created_at  timestamptz not null default now()
);

create table if not exists public.vacancies (
  id               uuid primary key default gen_random_uuid(),
  company_id       uuid not null references public.companies(id) on delete cascade,
  title            text not null,
  city             text default '',
  employment_type  text default 'full_time' check (employment_type in ('full_time','part_time','internship','remote')),
  salary           text default '',
  description      text default '',
  requirements     text default '',
  status           text not null default 'open' check (status in ('open','closed')),
  created_at       timestamptz not null default now()
);

create table if not exists public.applications (
  id            uuid primary key default gen_random_uuid(),
  vacancy_id    uuid not null references public.vacancies(id) on delete cascade,
  candidate_id  uuid not null references public.profiles(id) on delete cascade,
  status        text not null default 'new' check (status in ('new','viewed','interview','offer','rejected','hired')),
  note          text default '',
  created_at    timestamptz not null default now(),
  updated_at    timestamptz not null default now(),
  unique (vacancy_id, candidate_id)
);

create table if not exists public.application_events (
  id              bigint generated always as identity primary key,
  application_id  uuid not null references public.applications(id) on delete cascade,
  status          text not null,
  created_at      timestamptz not null default now()
);

create index if not exists vacancies_company_idx on public.vacancies(company_id);
create index if not exists applications_vacancy_idx on public.applications(vacancy_id);
create index if not exists applications_candidate_idx on public.applications(candidate_id);
create index if not exists events_app_idx on public.application_events(application_id);

-- ============ TRIGGERS ============

-- Create a profile row automatically on sign-up (role + name come from sign-up metadata)
create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = public as $$
declare r text := coalesce(new.raw_user_meta_data->>'role','candidate');
begin
  if r not in ('candidate','employer') then r := 'candidate'; end if;
  insert into public.profiles (id, role, full_name)
  values (new.id, r, coalesce(new.raw_user_meta_data->>'full_name',''));
  if r = 'candidate' then
    insert into public.candidate_profiles (user_id) values (new.id);
  end if;
  return new;
end $$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users
  for each row execute function public.handle_new_user();

-- Keep a status history so candidates see a timeline
create or replace function public.log_application_status()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  if tg_op = 'INSERT' or new.status is distinct from old.status then
    insert into public.application_events (application_id, status) values (new.id, new.status);
  end if;
  new.updated_at := now();
  return new;
end $$;

drop trigger if exists applications_status_log on public.applications;
create trigger applications_status_log before update on public.applications
  for each row execute function public.log_application_status();

create or replace function public.log_application_insert()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  insert into public.application_events (application_id, status) values (new.id, new.status);
  return new;
end $$;

drop trigger if exists applications_insert_log on public.applications;
create trigger applications_insert_log after insert on public.applications
  for each row execute function public.log_application_insert();

-- Candidates may only create applications with status 'new' and may not change status
create or replace function public.guard_application()
returns trigger language plpgsql set search_path = public as $$
begin
  if tg_op = 'INSERT' then
    new.status := 'new';
    new.candidate_id := auth.uid();
  elsif tg_op = 'UPDATE' then
    if new.candidate_id <> old.candidate_id or new.vacancy_id <> old.vacancy_id then
      raise exception 'not allowed';
    end if;
  end if;
  return new;
end $$;

drop trigger if exists applications_guard on public.applications;
create trigger applications_guard before insert or update on public.applications
  for each row execute function public.guard_application();

-- ============ HELPERS ============

create or replace function public.my_role() returns text
language sql stable security definer set search_path = public as $$
  select role from public.profiles where id = auth.uid()
$$;

-- true when the current user is the employer of a vacancy this candidate applied to
create or replace function public.is_employer_of(cand uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select exists (
    select 1 from public.applications a
    join public.vacancies v on v.id = a.vacancy_id
    join public.companies c on c.id = v.company_id
    where a.candidate_id = cand and c.owner_id = auth.uid()
  )
$$;

create or replace function public.owns_vacancy(vac uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select exists (
    select 1 from public.vacancies v join public.companies c on c.id = v.company_id
    where v.id = vac and c.owner_id = auth.uid()
  )
$$;

-- ============ API ACCESS ============
-- Only signed-in users reach these tables; row level security below decides which rows.
grant usage on schema public to authenticated;
grant select, insert, update, delete on
  public.profiles, public.candidate_profiles, public.companies,
  public.vacancies, public.applications, public.application_events
  to authenticated;
grant execute on function public.my_role(), public.is_employer_of(uuid), public.owns_vacancy(uuid) to authenticated;

-- ============ ROW LEVEL SECURITY ============

alter table public.profiles            enable row level security;
alter table public.candidate_profiles  enable row level security;
alter table public.companies           enable row level security;
alter table public.vacancies           enable row level security;
alter table public.applications        enable row level security;
alter table public.application_events  enable row level security;

-- profiles
drop policy if exists "profiles read" on public.profiles;
create policy "profiles read" on public.profiles for select
  using (id = auth.uid() or public.is_employer_of(id));
drop policy if exists "profiles update own" on public.profiles;
create policy "profiles update own" on public.profiles for update
  using (id = auth.uid()) with check (id = auth.uid() and role = public.my_role());

-- candidate_profiles
drop policy if exists "cand read" on public.candidate_profiles;
create policy "cand read" on public.candidate_profiles for select
  using (user_id = auth.uid() or public.is_employer_of(user_id));
drop policy if exists "cand update own" on public.candidate_profiles;
create policy "cand update own" on public.candidate_profiles for update
  using (user_id = auth.uid()) with check (user_id = auth.uid());

-- companies: public to read, owner (employer) to write
drop policy if exists "companies read" on public.companies;
create policy "companies read" on public.companies for select using (true);
drop policy if exists "companies insert" on public.companies;
create policy "companies insert" on public.companies for insert
  with check (owner_id = auth.uid() and public.my_role() = 'employer');
drop policy if exists "companies update" on public.companies;
create policy "companies update" on public.companies for update
  using (owner_id = auth.uid()) with check (owner_id = auth.uid());

-- vacancies: open ones are public, owner sees and edits all of theirs
drop policy if exists "vacancies read" on public.vacancies;
create policy "vacancies read" on public.vacancies for select
  using (status = 'open' or public.owns_vacancy(id)
         or exists (select 1 from public.applications a where a.vacancy_id = id and a.candidate_id = auth.uid()));
drop policy if exists "vacancies insert" on public.vacancies;
create policy "vacancies insert" on public.vacancies for insert
  with check (exists (select 1 from public.companies c where c.id = company_id and c.owner_id = auth.uid()));
drop policy if exists "vacancies update" on public.vacancies;
create policy "vacancies update" on public.vacancies for update
  using (public.owns_vacancy(id))
  with check (exists (select 1 from public.companies c where c.id = company_id and c.owner_id = auth.uid()));
drop policy if exists "vacancies delete" on public.vacancies;
create policy "vacancies delete" on public.vacancies for delete using (public.owns_vacancy(id));

-- applications
drop policy if exists "apps read" on public.applications;
create policy "apps read" on public.applications for select
  using (candidate_id = auth.uid() or public.owns_vacancy(vacancy_id));
drop policy if exists "apps insert" on public.applications;
create policy "apps insert" on public.applications for insert
  with check (public.my_role() = 'candidate'
    and exists (select 1 from public.vacancies v where v.id = vacancy_id and v.status = 'open'));
drop policy if exists "apps update employer" on public.applications;
create policy "apps update employer" on public.applications for update
  using (public.owns_vacancy(vacancy_id)) with check (public.owns_vacancy(vacancy_id));
drop policy if exists "apps delete own" on public.applications;
create policy "apps delete own" on public.applications for delete
  using (candidate_id = auth.uid());

-- events
drop policy if exists "events read" on public.application_events;
create policy "events read" on public.application_events for select
  using (exists (select 1 from public.applications a where a.id = application_id
                 and (a.candidate_id = auth.uid() or public.owns_vacancy(a.vacancy_id))));

-- ============ CV STORAGE ============

insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('cvs', 'cvs', false, 5242880, array['application/pdf'])
on conflict (id) do nothing;

-- files live at cvs/<user id>/cv.pdf
drop policy if exists "cv own read" on storage.objects;
create policy "cv own read" on storage.objects for select
  using (bucket_id = 'cvs' and ((storage.foldername(name))[1] = auth.uid()::text
         or public.is_employer_of(((storage.foldername(name))[1])::uuid)));
drop policy if exists "cv own insert" on storage.objects;
create policy "cv own insert" on storage.objects for insert
  with check (bucket_id = 'cvs' and (storage.foldername(name))[1] = auth.uid()::text);
drop policy if exists "cv own update" on storage.objects;
create policy "cv own update" on storage.objects for update
  using (bucket_id = 'cvs' and (storage.foldername(name))[1] = auth.uid()::text);
drop policy if exists "cv own delete" on storage.objects;
create policy "cv own delete" on storage.objects for delete
  using (bucket_id = 'cvs' and (storage.foldername(name))[1] = auth.uid()::text);
