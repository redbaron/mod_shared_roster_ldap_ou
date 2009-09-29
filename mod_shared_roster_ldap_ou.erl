%%%----------------------------------------------------------------------
%%% File    : mod_shared_roster_ldap_ou.erl
%%% Author  : Maxim Ivanov <ivanov.maxim@gmail.com
%%% Purpose : Shared roster from LDAP OU's
%%% Created : 28 Sep 2009 by Maxim Ivanov <ivanov.maxim@gmail.com
%%%
%%% TODO: add support to local ldap filters and local dn filters

-module(mod_shared_roster_ldap_ou).
-author('ivanov.maxim@gmail.com').

-behavior(gen_mod).
-behavior(gen_server).

-define(SUPERVISOR, ejabberd_sup).
-define(PROCNAME, mod_shared_roster_ldap_ou).
-define(LDAP_REQUEST_TIMEOUT, 10000).



%% gen_mod callbacks
-export([start/2, stop/1]).

%% gen_server callbacks
-export([init/1, terminate/2, handle_call/3, handle_cast/2,
         handle_info/2, code_change/3]).
%% API
-export([start_link/2,get_user_roster/2]).

-include("ejabberd.hrl").
-include("eldap/eldap.hrl").
-include("jlib.hrl").
-include("mod_roster.hrl").

-record(state, {
       host,
       eldap_id,
       servers,
       port,
       rootdn,
       base,
       password,
       encrypt,
       uids,            % list of {attr,template} which is used to match user name in LDAP
       uids_only,       % list of attrs in uids field
       user_filter,     % filter to find users within groups (build from ldap_filter)
       search_filter,   % user_filter with replaced %u to *
       group_filter,    % group filter (should find only OU right now)
       user_descr,      % attrribute to read user name from
       group_descr      % attribute to read group name from
      }).

-record(roster_entry, {
    dn,
    name,
    descr}).    

%% Unused callbacks.
handle_cast(_Request, State) ->
    {noreply, State}.
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.
handle_info(_Info, State) ->
    {noreply, State}.
%% -----


%%====================================================================
%% gen_mod callbacks
%%====================================================================
start(Host, Opts) ->
    Proc = gen_mod:get_module_proc(Host, ?MODULE),
    PingSpec = {Proc, {?MODULE, start_link, [Host, Opts]},
                transient, 2000, worker, [?MODULE]},
    supervisor:start_child(?SUPERVISOR, PingSpec).

stop(Host) ->
    Proc = gen_mod:get_module_proc(Host, ?MODULE),
    gen_server:call(Proc, stop),
    supervisor:terminate_child(?SUPERVISOR, Proc),
    supervisor:delete_child(?SUPERVISOR, Proc).
    
%%====================================================================
%% gen_server callbacks
%%====================================================================
init([Host, Opts]) ->
    ?INFO_MSG("Starting ~p",[?MODULE]),
    State = parse_options(Host, Opts),
    ejabberd_hooks:add(roster_get, Host,
               ?MODULE, get_user_roster, 70),
    %ejabberd_hooks:add(roster_in_subscription, Host,
    %               ?MODULE, in_subscription, 30),
    %ejabberd_hooks:add(roster_out_subscription, Host,
    %               ?MODULE, out_subscription, 30),
    %ejabberd_hooks:add(roster_get_subscription_lists, Host,
    %           ?MODULE, get_subscription_lists, 70),
    %ejabberd_hooks:add(roster_get_jid_info, Host,
    %               ?MODULE, get_jid_info, 70),
    %ejabberd_hooks:add(roster_process_item, Host,
    %               ?MODULE, process_item, 50),
    eldap:start_link(State#state.eldap_id,
        State#state.servers,
        State#state.port,
        State#state.rootdn,
        State#state.password,
        State#state.encrypt),
    {ok, State}.
    
terminate(_Reason, State) ->
    Host = State#state.host,
    ejabberd_hooks:delete(roster_get, Host,
              ?MODULE, get_user_roster, 70),
    %ejabberd_hooks:delete(roster_in_subscription, Host,
    %              ?MODULE, in_subscription, 30),
    %ejabberd_hooks:delete(roster_out_subscription, Host,
    %              ?MODULE, out_subscription, 30),
    %ejabberd_hooks:delete(roster_get_subscription_lists, Host,
    %              ?MODULE, get_subscription_lists, 70),
    %ejabberd_hooks:delete(roster_get_jid_info, Host,
    %              ?MODULE, get_jid_info, 70),
    %ejabberd_hooks:delete(roster_process_item, Host,
    %          ?MODULE, process_item, 50).
    ok.

% almost everyithing is copied from mod_shared_roster
get_user_roster(Items, US) ->
    {U, S} = US,
    DisplayedGroups = get_user_displayed_groups(US),
    %% Get shared roster users in all groups and remove self: 
    SRUsers = 
    lists:foldl(
      fun(#roster_entry{descr=GroupName} = Group, Acc1) ->
          lists:foldl(
            fun(#roster_entry{name=UserName,descr=UserDescr} = _User, Acc2) ->
                if UserName == US -> Acc2;
                   true -> dict:append(UserName, 
                           {GroupName,UserDescr},
                           Acc2)
                end
            end, Acc1, get_group_users(S, Group))
      end, dict:new(), DisplayedGroups),

    %%If partially subscribed users are also in shared roster, show them as
    %% totally subscribed and remove from shared roster:
    {NewItems1, SRUsersRest} =
    lists:mapfoldl(
      fun(Item, SRUsers1) ->
          {_, _, {U1, S1, _}} = Item#roster.usj,
          US1 = {U1, S1},
          case dict:find(US1, SRUsers1) of
              {ok, _GroupNames} ->
              {Item#roster{subscription = both, ask = none},
               dict:erase(US1, SRUsers1)};
              error ->
              {Item, SRUsers1}
          end
      end, SRUsers, Items),

    %% Export items in roster format:
    SRItems = [#roster{usj = {U, S, {U1, S1, ""}},
               us = US,
               jid = {U1, S1, ""},
               name = element(2,lists:nth(1,GroupNames)),
               subscription = both,
               ask = none,
               groups = element(1,lists:unzip(GroupNames))} ||
          {{U1, S1}, GroupNames} <- dict:to_list(SRUsersRest)],
    SRItems ++ NewItems1.

%% @doc Get the list of groups that are displayed to this user
%% searches according to group_filter settings and uses gdescr attr to 
%% retrieve name, if it's not possible then tries to extract name
%% from DN
get_user_displayed_groups({User, Host}) ->
    make_request(Host, {get_user_displayed_groups, User}, []).

%% @doc get members of group
get_group_users(Host, Group) ->
    make_request(Host, {get_group_users, Group}, []).


%%====================================================================
%% API
%%====================================================================
start_link(Host, Opts) ->
    Proc = gen_mod:get_module_proc(Host, ?MODULE),
    gen_server:start_link({local, Proc}, ?MODULE, [Host, Opts], []).

%%%-----------------------
%%% Actual logic
%%%-----------------------

handle_call({get_user_displayed_groups, _User}, _From, State) ->
    SearchArgs = #eldap_search{
        base = State#state.base,
        filter = State#state.group_filter,
        attributes = [ State#state.group_descr ]
    },
    
    GdescrAttr = State#state.group_descr,
    Reply = map_ldap_search(State#state.eldap_id,SearchArgs,
        fun(#eldap_entry{object_name = DN, attributes = Attrs}) ->
            GroupDescr = case Attrs of
                [{GdescrAttr, Descr}] -> Descr;
                _ ->  extract_group_name(DN)
            end,
            case GroupDescr of
                undefined -> undefined;
                _ -> #roster_entry{ dn = DN, descr = GroupDescr }
            end
       end
    ),
    {reply, Reply, State};


handle_call({get_group_users,  Group}, _From, State) ->
    DN = Group#roster_entry.dn,
    SearchArgs = #eldap_search{
        base = DN,
        filter = State#state.search_filter,
        attributes = State#state.uids_only
    },
    Reply = case eldap:search(State#state.eldap_id, SearchArgs) of
        #eldap_search_result{entries = Es} ->
            search_users(Es,State);
        _ -> error
    end,
    {reply, Reply, State};

handle_call(stop, _From, State) ->
    {stop, normal, ok, State};

handle_call(_Request, _From, State) ->
    {reply, bad_request, State}.

search_users(Entries,State) ->
    Host = State#state.host,
    UIDs = State#state.uids,
    UserDescrAttr = State#state.user_descr,
    lists:map(
      fun(#eldap_entry{object_name = _DN,attributes=Attrs}) ->
          case eldap_utils:find_ldap_attrs(UIDs, Attrs) of
          {U, UIDAttrFormat} ->
              case eldap_utils:get_user_part(U, UIDAttrFormat) of
              {ok, Username} ->
                  case ejabberd_auth:is_user_exists(Username, Host) of
                  true -> #roster_entry{
                            name={Username,Host},
                            descr=extract_user_descr(Username,Attrs,UserDescrAttr)
                            };
                   _ -> []
                   end;
              _ -> []
              end;
          _ -> []
          end
      end, Entries).

%%%-----------------------
%%% Utility functions
%%%-----------------------

%parse options, most of funct is copied from auth_ldap module
parse_options(Host, Opts) ->
    Eldap_ID = atom_to_list(gen_mod:get_module_proc(Host, ?PROCNAME)),
    LDAPServers = case gen_mod:get_opt(ldap_servers, Opts, undefined) of
              undefined ->
                ejabberd_config:get_local_option({ldap_servers, Host});
              S -> S
          end,
    LDAPEncrypt = case gen_mod:get_opt(ldap_encrypt, Opts, undefined) of
              undefined ->
                ejabberd_config:get_local_option({ldap_encrypt, Host});
              E -> E
              end,
    LDAPPortTemp = case gen_mod:get_opt(ldap_port, Opts, undefined) of
               undefined ->
                ejabberd_config:get_local_option({ldap_port, Host});
               PT -> PT
               end,
    LDAPPort = case LDAPPortTemp of
           undefined ->
               case LDAPEncrypt of
                tls -> ?LDAPS_PORT;
                starttls -> ?LDAP_PORT;
                _ -> ?LDAP_PORT
               end;
           P -> P
           end,
    LDAPBase = case gen_mod:get_opt(ldap_base, Opts, undefined) of
           undefined ->
               ejabberd_config:get_local_option({ldap_base, Host});
           B -> B
           end,
    UIDs = case gen_mod:get_opt(ldap_uids, Opts, undefined) of
        undefined ->
            case ejabberd_config:get_local_option({ldap_uids, Host}) of
                undefined -> [{"uid", "%u"}];
                UI -> eldap_utils:uids_domain_subst(Host, UI)
            end;
        UI -> eldap_utils:uids_domain_subst(Host, UI)
        end,
        
    RootDN = case gen_mod:get_opt(ldap_rootdn, Opts, undefined) of
         undefined ->
             case ejabberd_config:get_local_option({ldap_rootdn, Host}) of
                undefined -> "";
                RDN -> RDN
             end;
         RDN -> RDN
         end,
    Password = case gen_mod:get_opt(ldap_password, Opts, undefined) of
           undefined ->
               case ejabberd_config:get_local_option({ldap_password, Host}) of
               undefined -> "";
               Pass -> Pass
               end;
           Pass -> Pass
           end,
           
    SubFilter = lists:flatten(eldap_utils:generate_subfilter(UIDs)),
    UserFilter = case gen_mod:get_opt(ldap_filter, Opts, undefined) of
            undefined ->
                case ejabberd_config:get_local_option({ldap_filter, Host}) of
                    undefined -> SubFilter;
                    "" -> SubFilter;
                    F -> "(&" ++ SubFilter ++ F ++ ")"
                end;
            "" -> SubFilter;
            F -> "(&" ++ SubFilter ++ F ++ ")"
            end,
    {ok, UserSearchFilter} = eldap_filter:parse(
            eldap_filter:do_sub(UserFilter, [{"%u","*"}])),
    UserDescr = gen_mod:get_opt(ldap_udescr, Opts, undefined),
    {ok, GroupFilter} = eldap_filter:parse( gen_mod:get_opt(ldap_gfilter, Opts, "(ou=*)")),
    GroupDescr = gen_mod:get_opt(ldap_gdescr, Opts, undefined),
    %UIDs_only used to build attributes in LDAP request, we need bith description attrs and name matching attrs
    UIDs_Only = [ UserDescr | lists:map(fun({Attr,_Value}) -> Attr end, UIDs) ],  
    
    State = #state{host = Host,
       eldap_id = Eldap_ID,
       servers = LDAPServers,
       port = LDAPPort,
       rootdn = RootDN,
       base = LDAPBase,
       password = Password,
       encrypt = LDAPEncrypt,
       uids = UIDs,
       uids_only = UIDs_Only,
       user_filter =  UserFilter,
       search_filter = UserSearchFilter,
       group_filter = GroupFilter,
       user_descr = UserDescr,
       group_descr = GroupDescr
      },
      ?INFO_MSG("~p configured with ~p",[?MODULE,State]),
      State.

map_ldap_search(EldapID, #eldap_search{} = SearchArgs, Fun) ->
    case eldap:search(EldapID, SearchArgs) of
        #eldap_search_result{entries = Es} -> lists:map(Fun,Es);
        _ -> []
    end.
  
%% @doc extracts group name as ou= name from DN
%% if it's doesn't start from ou then return undefined
extract_group_name(DN) ->
    case DN of 
        "ou=" ++ Tail -> string:sub_word(Tail,1,$,);
        _ -> undefined
    end.

%% @doc extracts description of user from it's attrs
%% fallbacks to Username
extract_user_descr(Username,Attrs,DescrAttr) ->
    case lists:keytake(DescrAttr,1,Attrs) of
        {value,{_,Descr},_} -> Descr;
        false -> Username
    end.

    
    
make_request(Host, Request, Fallback) ->
    Proc = gen_mod:get_module_proc(Host, ?MODULE),
    case catch gen_server:call(Proc, Request, ?LDAP_REQUEST_TIMEOUT) of
        {'EXIT', _} ->
            Fallback;
        Result ->
            Result
    end.