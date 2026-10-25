-- Cijian: authenticated users can read only their own progress.
-- Writes use a bounded, atomic patch RPC with optimistic concurrency.
create table if not exists public.cijian_user_progress (
  user_id uuid primary key references auth.users(id) on delete cascade,
  revision bigint not null default 0,
  state jsonb not null default '{}'::jsonb,
  updated_at timestamptz not null default now(),
  constraint cijian_state_object check (jsonb_typeof(state) = 'object')
);
alter table public.cijian_user_progress enable row level security;
revoke all on public.cijian_user_progress from anon, authenticated;
grant select on public.cijian_user_progress to authenticated;
do $$ begin
  if not exists (select 1 from pg_policies where schemaname='public' and tablename='cijian_user_progress' and policyname='cijian_read_own_progress') then
    create policy cijian_read_own_progress on public.cijian_user_progress
      for select to authenticated using ((select auth.uid())=user_id);
  end if;
end $$;

create or replace function public.cijian_sync_patch(p_expected bigint,p_patch jsonb)
returns jsonb language plpgsql security definer set search_path = '' as $$
declare
  owner_id uuid := auth.uid();
  current_revision bigint;
  current_state jsonb;
  next_state jsonb;
  map_name text;
  key_name text;
begin
  if owner_id is null then raise exception 'Authentication required' using errcode='42501'; end if;
  if jsonb_typeof(p_patch) is distinct from 'object' or octet_length(p_patch::text)>2097152 then
    raise exception 'Invalid or oversized patch' using errcode='22023';
  end if;
  for key_name in select jsonb_object_keys(p_patch) loop
    if not (key_name=any(array['version','layoutVersion','dataVersion','book','direction','records','reverse','aliases','definitions','analyses','starred','last','updatedAt','_sync'])) then
      raise exception 'Unsupported progress field' using errcode='22023';
    end if;
  end loop;
  insert into public.cijian_user_progress(user_id) values(owner_id) on conflict(user_id) do nothing;
  select revision,state into current_revision,current_state from public.cijian_user_progress where user_id=owner_id for update;
  if current_revision<>p_expected then
    return jsonb_build_object('ok',false,'revision',current_revision,'state',current_state);
  end if;
  next_state := current_state || (p_patch - array['records','reverse','aliases','definitions','analyses','starred','last','_sync']);
  foreach map_name in array array['records','reverse','aliases','definitions','analyses','starred','last'] loop
    if p_patch ? map_name then
      if jsonb_typeof(p_patch->map_name) is distinct from 'object' then raise exception 'Invalid progress map' using errcode='22023'; end if;
      next_state:=jsonb_set(next_state,array[map_name],coalesce(current_state->map_name,'{}'::jsonb)||(p_patch->map_name),true);
    end if;
  end loop;
  if p_patch ? '_sync' then
    next_state:=jsonb_set(next_state,'{_sync}',jsonb_build_object(
      'clock',greatest(coalesce((current_state#>>'{_sync,clock}')::bigint,0),coalesce((p_patch#>>'{_sync,clock}')::bigint,0)),
      'clocks',coalesce(current_state#>'{_sync,clocks}','{}'::jsonb)||coalesce(p_patch#>'{_sync,clocks}','{}'::jsonb)
    ),true);
  end if;
  if octet_length(next_state::text)>33554432 then raise exception 'Progress quota exceeded' using errcode='22023'; end if;
  update public.cijian_user_progress set state=next_state,revision=current_revision+1,updated_at=now() where user_id=owner_id;
  return jsonb_build_object('ok',true,'revision',current_revision+1);
end $$;
revoke all on function public.cijian_sync_patch(bigint,jsonb) from public, anon;
grant execute on function public.cijian_sync_patch(bigint,jsonb) to authenticated;
