import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import time
import threading
import json
import urllib.request

spec=importlib.util.spec_from_file_location('panel',Path(__file__).resolve().parents[1]/'server.py')
p=importlib.util.module_from_spec(spec); spec.loader.exec_module(p)
NODE='vless://00000000-0000-4000-8000-000000000001@192.0.2.10:443?encryption=none&security=tls&sni=test.example.com&type=ws&host=test.example.com&path=%2Ftest-ws#TEST'

class PanelTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();p.DATA=Path(self.tmp.name);p.DB=p.DATA/'test.db';p.init()
        self.s=p.settings();self.s['token']='test'
        self.g=dict(id='test',domain='node.example.com',zone='a'*32,node=NODE,ips=['1.1.1.1','2.2.2.2','3.3.3.3'],mode='proxy',enabled=True,current='1.1.1.1')
    def tearDown(self): self.tmp.cleanup()
    def result(self,g,ip,s):return dict(ip=ip,ok=ip!='2.2.2.2',ms=1 if ip=='3.3.3.3' else 30)
    def test_rewrite_preserves_original_parameters(self):
        new=p.rewritten(NODE,'node.example.com')
        self.assertEqual(new.split('?',1)[1],NODE.split('?',1)[1]);self.assertIn('@node.example.com:443?',new)
        out=p.outbound(NODE,'3.3.3.3');self.assertEqual(out['server'],'3.3.3.3');self.assertEqual(out['tls']['server_name'],'test.example.com');self.assertEqual(out['transport']['path'],'/test-ws')
    def test_rotation_skips_failed_candidate(self):
        with patch.object(p,'probe',side_effect=self.result),patch.object(p.Cloudflare,'update') as update:
            p.rotate(self.g,self.s,True)
            update.assert_called_once_with('a'*32,'node.example.com','3.3.3.3')
        self.assertEqual(p.groups()[0]['current'],'3.3.3.3')
    def test_cloudflare_failure_preserves_current(self):
        with patch.object(p,'probe',side_effect=self.result),patch.object(p.Cloudflare,'update',side_effect=RuntimeError('denied')):
            p.rotate(self.g,self.s,True)
        self.assertEqual(p.groups()[0]['current'],'1.1.1.1');self.assertEqual(p.groups()[0]['error'],'denied')
    def test_all_failed_preserves_dns(self):
        with patch.object(p,'probe',side_effect=lambda g,ip,s:dict(ip=ip,ok=False)),patch.object(p.Cloudflare,'update') as update:
            p.rotate(self.g,self.s,True);update.assert_not_called()
        self.assertEqual(p.groups()[0]['current'],'1.1.1.1')
    def test_probe_only_never_updates_dns(self):
        with patch.object(p,'probe',side_effect=self.result),patch.object(p.Cloudflare,'update') as update:
            p.rotate(self.g,self.s,False);update.assert_not_called()
    def test_conflicting_address_family_is_refused(self):
        cf=p.Cloudflare('test')
        with patch.object(cf,'call',return_value={'result':[{'type':'AAAA'}]}) as call:
            with self.assertRaises(RuntimeError):cf.update('a'*32,'node.example.com','1.1.1.1')
            self.assertEqual(call.call_count,1)
    def test_background_health_failure_triggers_rotation(self):
        self.g.update(next_run=time.time()+3600,next_check=0);p.put(self.g)
        with patch.object(p,'probe',return_value={'ok':False}),patch.object(p,'rotate') as rotate:
            self.assertTrue(p.run(scheduled=True))
            self.assertTrue(p.RUNNING.acquire(timeout=3));p.RUNNING.release()
            rotate.assert_called_once()
    def test_healthy_node_does_not_rotate_early(self):
        self.g.update(next_run=time.time()+3600,next_check=0);p.put(self.g)
        with patch.object(p,'probe',return_value={'ok':True}),patch.object(p,'rotate') as rotate:
            self.assertTrue(p.run(scheduled=True));self.assertTrue(p.RUNNING.acquire(timeout=3));p.RUNNING.release();rotate.assert_not_called()
    def test_manual_switch_updates_only_selected_ip(self):
        with patch.object(p,'probe',return_value={'ip':'3.3.3.3','ok':True}),patch.object(p.Cloudflare,'update') as update:
            p.switch_ip(self.g,'3.3.3.3',self.s)
            update.assert_called_once_with('a'*32,'node.example.com','3.3.3.3')
        saved=p.groups()[0]
        self.assertEqual(saved['current'],'3.3.3.3')
        self.assertEqual(saved['manual_switch']['status'],'success')
        self.assertGreater(saved['next_run'],time.time()+3500)
    def test_manual_switch_failed_probe_preserves_current(self):
        with patch.object(p,'probe',return_value={'ip':'3.3.3.3','ok':False,'error':'offline'}),patch.object(p.Cloudflare,'update') as update:
            p.switch_ip(self.g,'3.3.3.3',self.s);update.assert_not_called()
        self.assertEqual(p.groups()[0]['current'],'1.1.1.1')
        self.assertEqual(p.groups()[0]['manual_switch']['status'],'failed')
    def test_manual_switch_cloudflare_failure_preserves_current(self):
        with patch.object(p,'probe',return_value={'ip':'3.3.3.3','ok':True}),patch.object(p.Cloudflare,'update',side_effect=RuntimeError('denied')):
            p.switch_ip(self.g,'3.3.3.3',self.s)
        self.assertEqual(p.groups()[0]['current'],'1.1.1.1')
        self.assertEqual(p.groups()[0]['manual_switch']['error'],'denied')
    def test_manual_switch_rejects_ip_outside_pool_and_releases_lock(self):
        p.put(self.g)
        with self.assertRaises(ValueError):p.start_switch('test','4.4.4.4')
        self.assertFalse(p.RUNNING.locked())
    def test_batch_extracts_connection_ip_only_and_deduplicates(self):
        ipv6=NODE.replace('192.0.2.10','[2001:db8::1]')
        ipv6long=NODE.replace('192.0.2.10','[2001:0db8:0:0:0:0:0:1]')
        domain=NODE.replace('192.0.2.10','node.example.com')
        d=p.extract_ips('\n'.join([NODE,NODE,ipv6,ipv6long,domain,'garbage']))
        self.assertEqual(d['ips'],['192.0.2.10','2001:db8::1'])
        self.assertEqual(d['duplicates'],2)
        self.assertEqual(d['domain_count'],1)
        self.assertEqual(d['invalid'],1)
    def test_extract_does_not_require_supported_transport(self):
        d=p.extract_ips(NODE.replace('type=ws','type=xhttp'))
        self.assertEqual(d['ips'],['192.0.2.10'])
    def test_mixed_ip_formats_are_partitioned_by_port(self):
        d=p.extract_ips('1.1.1.1:443\n1.1.1.1 8443\n1.1.1.1：443\n2.2.2.2 8443\n[2001:db8::1]:8443\n2001:db8::2 443')
        self.assertEqual(d['port_groups']['443']['ips'],['1.1.1.1','2001:db8::2'])
        self.assertEqual(d['port_groups']['8443']['ips'],['1.1.1.1','2.2.2.2','2001:db8::1'])
        self.assertEqual(d['port_groups']['443']['duplicates'],1)
        self.assertEqual(d['invalid'],0)
    def test_other_ports_and_bad_ports_do_not_enter_pools(self):
        d=p.extract_ips('1.1.1.1:80\n1.1.1.1:99999\n1.1.1.1:0\n1.1.1.1:bad')
        self.assertEqual(d['ips'],[])
        self.assertEqual(d['other_port_count'],1)
        self.assertEqual(d['invalid'],3)
    def test_port_names_are_idempotent(self):
        self.assertEqual(p.domain_for_port('node.example.com',443),'node-1.example.com')
        self.assertEqual(p.domain_for_port('node-1.example.com',443),'node-1.example.com')
        self.assertEqual(p.domain_for_port('node-1.example.com',8443),'node-2.example.com')
        self.assertEqual(p.domain_for_port('node-2.example.com',443),'node-1.example.com')
    def test_group_uses_actual_node_port_for_domain(self):
        g=p.validate_group(dict(self.g,node=NODE.replace(':443?',':8443?')))
        self.assertEqual(g['domain'],'node-2.example.com');self.assertEqual(g['port'],8443)
        self.assertIn('@node-2.example.com:8443?',p.rewritten(g['node'],g['domain']))
    def test_raw_import_builds_two_groups_with_original_template_fields(self):
        d=dict(domain='node.example.com',zone='a'*32,node=NODE,text='1.1.1.1:443\n2.2.2.2 8443')
        gs=p.prepare_port_groups(d,[])
        self.assertEqual([g['domain'] for g in gs],['node-1.example.com','node-2.example.com'])
        self.assertEqual([g['port'] for g in gs],[443,8443])
        self.assertEqual([g['ips'] for g in gs],[['1.1.1.1'],['2.2.2.2']])
        self.assertEqual(gs[1]['node'].split('?',1)[1],NODE.split('?',1)[1])
        self.assertFalse(gs[0]['enabled'])
    def test_raw_import_requires_template(self):
        with self.assertRaises(ValueError):p.prepare_port_groups(dict(domain='node.example.com',zone='a'*32,text='1.1.1.1:443'),[])
    def test_full_node_import_uses_each_ports_own_template(self):
        second=NODE.replace(':443?',':8443?').replace('test.example.com','different.example.com')
        gs=p.prepare_port_groups(dict(domain='node.example.com',zone='a'*32,text=NODE+'\n'+second),[])
        self.assertEqual(p.parse_node(gs[0]['node'])[1]['sni'],'test.example.com')
        self.assertEqual(p.parse_node(gs[1]['node'])[1]['sni'],'different.example.com')
    def test_import_append_retains_status_and_rejects_template_conflicts(self):
        existing=p.prepare_port_groups(dict(domain='node.example.com',zone='a'*32,node=NODE,text='1.1.1.1:443',enabled=True),[])
        d=dict(domain='node.example.com',zone='a'*32,node=NODE,text='2.2.2.2:443')
        g=p.prepare_port_groups(d,existing)[0]
        self.assertTrue(g['enabled']);self.assertEqual(g['ips'],['1.1.1.1','2.2.2.2'])
        d['node']=NODE.replace('test.example.com','conflict.example.com')
        with self.assertRaises(ValueError):p.prepare_port_groups(d,existing)
    def test_failed_candidates_leave_normal_pool_and_are_not_reprobed(self):
        with patch.object(p,'probe',side_effect=self.result),patch.object(p.Cloudflare,'update'):
            p.rotate(self.g,self.s,True)
        g=p.groups()[0]
        self.assertEqual(p.active_ips(g),['1.1.1.1','3.3.3.3'])
        self.assertGreater(g['failed_ips']['2.2.2.2']['next_retry'],time.time()+290)
        with patch.object(p,'probe',side_effect=self.result) as probe,patch.object(p.Cloudflare,'update'):
            p.rotate(g,self.s,True)
            self.assertNotIn('2.2.2.2',[call.args[1] for call in probe.call_args_list])
    def test_recovery_is_not_attempted_before_next_day(self):
        p.record_probe(self.g,{'ip':'2.2.2.2','ok':False})
        with patch.object(p,'probe') as probe:p.recover_failed(self.g,self.s);probe.assert_not_called()
    def test_recovered_ip_returns_to_original_group_without_dns_write(self):
        p.record_probe(self.g,{'ip':'2.2.2.2','ok':False})
        self.g['failed_ips']['2.2.2.2']['next_retry']=0
        with patch.object(p,'probe',return_value={'ip':'2.2.2.2','ok':True}),patch.object(p.Cloudflare,'update') as update:
            p.recover_failed(self.g,self.s);update.assert_not_called()
        self.assertNotIn('2.2.2.2',self.g['failed_ips'])
        self.assertIn('2.2.2.2',p.active_ips(self.g))
        self.assertEqual(self.g['domain'],'node.example.com')
    def test_still_failed_gets_another_day_and_keeps_first_failure_time(self):
        p.record_probe(self.g,{'ip':'2.2.2.2','ok':False})
        first=self.g['failed_ips']['2.2.2.2']['since']
        self.g['failed_ips']['2.2.2.2']['next_retry']=0
        with patch.object(p,'probe',return_value={'ip':'2.2.2.2','ok':False}):p.recover_failed(self.g,self.s)
        failed=self.g['failed_ips']['2.2.2.2']
        self.assertEqual(failed['since'],first);self.assertGreater(failed['next_retry'],time.time()+1790)
    def test_all_failed_waits_for_daily_recovery(self):
        with patch.object(p,'probe',side_effect=lambda g,ip,s:dict(ip=ip,ok=False)):
            p.rotate(self.g,self.s,True)
        self.assertEqual(p.active_ips(self.g),[])
        self.assertGreater(self.g['next_run'],time.time()+290)
        self.assertFalse(p.scheduled_due(self.g))
    def test_cloudflare_error_does_not_quarantine_healthy_node(self):
        with patch.object(p,'probe',return_value={'ip':'3.3.3.3','ok':True}),patch.object(p.Cloudflare,'update',side_effect=RuntimeError('API error')):
            p.switch_ip(self.g,'3.3.3.3',self.s)
        self.assertNotIn('3.3.3.3',self.g.get('failed_ips',{}))
    def test_quarantine_persists_across_restart_migration(self):
        p.record_probe(self.g,{'ip':'2.2.2.2','ok':False});p.put(self.g)
        retry=self.g['failed_ips']['2.2.2.2']['next_retry'];p.init()
        self.assertEqual(p.groups()[0]['failed_ips']['2.2.2.2']['next_retry'],retry)
    def test_existing_failed_results_are_migrated(self):
        self.g['results']=[{'ip':'2.2.2.2','ok':False,'error':'timeout'}];p.put(self.g)
        p.migrate_failed_pools()
        self.assertNotIn('2.2.2.2',p.active_ips(p.groups()[0]))
    def test_reimport_does_not_restore_failed_ip(self):
        existing=p.prepare_port_groups(dict(domain='node.example.com',zone='a'*32,node=NODE,text='1.1.1.1:443'),[])
        p.record_probe(existing[0],{'ip':'1.1.1.1','ok':False})
        g=p.prepare_port_groups(dict(domain='node.example.com',zone='a'*32,node=NODE,text='1.1.1.1:443\n2.2.2.2:443'),existing)[0]
        self.assertNotIn('1.1.1.1',p.active_ips(g))
        self.assertIn('2.2.2.2',p.active_ips(g))
    def test_paused_groups_get_recovery_but_no_dns_rotation(self):
        self.g['enabled']=False
        p.record_probe(self.g,{'ip':'2.2.2.2','ok':False});self.g['failed_ips']['2.2.2.2']['next_retry']=0;p.put(self.g)
        with patch.object(p,'probe',return_value={'ip':'2.2.2.2','ok':True}),patch.object(p,'rotate') as rotate:
            self.assertTrue(p.run(scheduled=True));self.assertTrue(p.RUNNING.acquire(timeout=3));p.RUNNING.release();rotate.assert_not_called()
        self.assertEqual(p.groups()[0]['failed_ips'],{})
    def test_port_import_http_succeeds_while_probe_is_running(self):
        node=NODE
        original=p.prepare_port_groups(dict(domain='busy',node=node,text='1.1.1.1:443'),[])[0]
        p.put(original)
        started=threading.Event();release=threading.Event()
        server=p.ThreadingHTTPServer(('127.0.0.1',0),p.Handler);server.password='test-password'
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        def slow_probe(g,ip,s):
            started.set();release.wait(5)
            return {'ip':ip,'ok':False,'error':'offline'}
        try:
            with patch.object(p,'probe',side_effect=slow_probe):
                self.assertTrue(p.run([original['id']],write=False))
                self.assertTrue(started.wait(2))
                body=dict(domain='busy',node=node,text='2.2.2.2:443\n3.3.3.3 8443')
                req=urllib.request.Request('http://127.0.0.1:'+str(server.server_port)+'/api/import-ports',data=json.dumps(body).encode(),headers={'Authorization':'Bearer test-password','Content-Type':'application/json'})
                with urllib.request.urlopen(req,timeout=2) as response:
                    self.assertEqual(response.status,200);self.assertEqual(len(json.load(response)['groups']),2)
                self.assertTrue(p.RUNNING.locked())
                release.set();self.assertTrue(p.RUNNING.acquire(timeout=3));p.RUNNING.release()
            gs={g['port']:g for g in p.groups()}
            self.assertEqual(gs[443]['ips'],['1.1.1.1','2.2.2.2'])
            self.assertIn('1.1.1.1',gs[443]['failed_ips'])
            self.assertEqual(gs[8443]['ips'],['3.3.3.3'])
        finally:
            release.set();server.shutdown();server.server_close();thread.join(2)
    def test_runtime_write_preserves_multiple_concurrent_appends(self):
        original=p.prepare_port_groups(dict(domain='append',node=NODE,text='1.1.1.1:443'),[])[0]
        p.put(original)
        p.import_port_groups(dict(domain='append',node=NODE,text='2.2.2.2:443'))
        p.import_port_groups(dict(domain='append',node=NODE,text='3.3.3.3:443'))
        original['current']='1.1.1.1';p.put_runtime(original)
        self.assertEqual(p.groups()[0]['ips'],['1.1.1.1','2.2.2.2','3.3.3.3'])
    def test_regular_config_write_can_still_remove_ip(self):
        p.put(self.g)
        self.g['ips']=['1.1.1.1'];p.put(self.g)
        self.assertEqual(p.groups()[0]['ips'],['1.1.1.1'])
    def test_detection_writes_keep_domain_list_order(self):
        for gid in ['first','second','third']:
            p.put(dict(self.g,id=gid,domain=gid+'.example.com'))
        first=p.groups()[0]
        first['checked']=time.time();p.put_runtime(first)
        self.assertEqual([g['id'] for g in p.groups()],['first','second','third'])
        second=p.groups()[1];second['error']='updated';p.put(second)
        self.assertEqual([g['id'] for g in p.groups()],['first','second','third'])
    def test_batch_append_keeps_existing_order_and_new_groups_at_end(self):
        p.import_port_groups(dict(domain='first',node=NODE,text='1.1.1.1:443'))
        p.import_port_groups(dict(domain='second',node=NODE,text='2.2.2.2:443'))
        p.import_port_groups(dict(domain='first',node=NODE,text='3.3.3.3:443\n4.4.4.4:8443'))
        self.assertEqual([g['domain'] for g in p.groups()],['first-1.example.com','second-1.example.com','first-2.example.com'])
    def test_latency_selection_chooses_fastest_instead_of_next_ip(self):
        def result(g,ip,s):return {'ip':ip,'ok':True,'ms':{'1.1.1.1':35,'2.2.2.2':100,'3.3.3.3':5}[ip]}
        with patch.object(p,'probe',side_effect=result),patch.object(p.Cloudflare,'update') as update:
            p.rotate(self.g,self.s,True)
            update.assert_called_once_with('a'*32,'node.example.com','3.3.3.3')
    def test_latency_tie_keeps_current_ip(self):
        with patch.object(p,'probe',side_effect=lambda g,ip,s:dict(ip=ip,ok=True,ms=10)),patch.object(p.Cloudflare,'update') as update:
            p.rotate(self.g,self.s,True)
            update.assert_called_once_with('a'*32,'node.example.com','1.1.1.1')
    def test_failed_low_latency_result_is_not_selected(self):
        def result(g,ip,s):return {'ip':ip,'ok':ip!='2.2.2.2','ms':{'1.1.1.1':35,'2.2.2.2':0,'3.3.3.3':50}[ip]}
        with patch.object(p,'probe',side_effect=result),patch.object(p.Cloudflare,'update') as update:
            p.rotate(self.g,self.s,True)
            update.assert_called_once_with('a'*32,'node.example.com','1.1.1.1')
    def test_saved_template_persists_and_can_be_updated(self):
        t=p.save_template({'name':'test template','node':NODE})
        p.init();self.assertEqual(p.templates()[0]['node'],NODE)
        updated=p.save_template(dict(t,name='renamed',node=NODE.replace(':443?',':8443?')))
        self.assertEqual(updated['id'],t['id']);self.assertEqual(updated['port'],8443)
        self.assertEqual(len(p.templates()),1)
    def test_saved_templates_can_be_selected_separately_for_each_port(self):
        first=p.save_template({'name':'443','node':NODE})
        second=p.save_template({'name':'8443','node':NODE.replace('test.example.com','other.example.com')})
        gs=p.prepare_port_groups(dict(domain='saved',text='1.1.1.1:443\n2.2.2.2:8443',template_443=first['id'],template_8443=second['id']),[])
        self.assertEqual(p.parse_node(gs[0]['node'])[1]['sni'],'test.example.com')
        self.assertEqual(p.parse_node(gs[1]['node'])[1]['sni'],'other.example.com')
        self.assertEqual(gs[1]['port'],8443)
    def test_template_edits_do_not_modify_existing_groups(self):
        t=p.save_template({'name':'test','node':NODE})
        gs=p.prepare_port_groups(dict(domain='saved',text='1.1.1.1:443',template_443=t['id']),[])
        p.put(gs[0]);original=p.groups()[0]['node']
        p.save_template(dict(t,node=NODE.replace('test.example.com','changed.example.com')))
        self.assertEqual(p.groups()[0]['node'],original)
    def test_deleted_template_id_is_rejected(self):
        with self.assertRaises(ValueError):p.prepare_port_groups(dict(domain='saved',text='1.1.1.1:443',template_443='missing'),[])
    def test_single_group_can_resolve_saved_template(self):
        t=p.save_template({'name':'test','node':NODE})
        g=p.validate_group(dict(domain='saved',template_id=t['id'],ips=['1.1.1.1']))
        self.assertEqual(g['node'],NODE)
    def test_cloudflare_delete_is_scoped_to_exact_domain_address_records(self):
        records=[{'id':'v4','name':'node.example.com','type':'A'}, {'id':'v6','name':'node.example.com','type':'AAAA'}, {'id':'txt','name':'node.example.com','type':'TXT'}, {'id':'other','name':'other.example.com','type':'A'}]
        cf=p.Cloudflare('test')
        with patch.object(cf,'call',side_effect=[{'result':records},{'success':True},{'success':True}]) as call:
            self.assertEqual(cf.delete_domain('a'*32,'node.example.com'),2)
            deleted=[c.args[1] for c in call.call_args_list if c.args[0]=='DELETE']
            self.assertEqual(deleted,['/zones/'+'a'*32+'/dns_records/v4','/zones/'+'a'*32+'/dns_records/v6'])
    def test_delete_removes_local_group_only_after_cloudflare_success(self):
        p.put(self.g)
        with patch.object(p,'settings',return_value=self.s),patch.object(p.Cloudflare,'delete_domain',return_value=1):
            self.assertEqual(p.delete_group('test'),1)
        self.assertEqual(p.groups(),[])
    def test_delete_failure_preserves_local_group(self):
        p.put(self.g)
        with patch.object(p,'settings',return_value=self.s),patch.object(p.Cloudflare,'delete_domain',side_effect=RuntimeError('HTTP 403')):
            with self.assertRaisesRegex(RuntimeError,'本地配置已保留'):p.delete_group('test')
        self.assertEqual(len(p.groups()),1)
    def test_delete_already_absent_cloudflare_record_succeeds(self):
        p.put(self.g)
        with patch.object(p,'settings',return_value=self.s),patch.object(p.Cloudflare,'call',return_value={'result':[]}) as call:
            self.assertEqual(p.delete_group('test'),0)
            self.assertEqual(call.call_count,1)
        self.assertEqual(p.groups(),[])
    def test_delete_requires_cloudflare_credentials(self):
        p.put(self.g)
        with self.assertRaisesRegex(ValueError,'Token'):p.delete_group('test')
        self.assertEqual(len(p.groups()),1)
    def test_partial_cloudflare_deletion_does_not_remove_local_configuration(self):
        p.put(self.g)
        records=[{'id':'v4','name':'node.example.com','type':'A'},{'id':'v6','name':'node.example.com','type':'AAAA'}]
        with patch.object(p,'settings',return_value=self.s),patch.object(p.Cloudflare,'call',side_effect=[{'result':records},{'success':True},RuntimeError('temporary failure')]):
            with self.assertRaises(RuntimeError):p.delete_group('test')
        self.assertEqual(len(p.groups()),1)
    def test_probe_retries_transient_failure_and_stops_on_success(self):
        with patch.object(p,'_probe',side_effect=[{'ok':False},{'ok':True}]) as probe:
            result=p.probe(self.g,'1.1.1.1',self.s)
        self.assertTrue(result['ok']);self.assertEqual(result['attempts'],2)
        self.assertEqual(probe.call_count,2)

    def test_probe_confirms_three_failures(self):
        with patch.object(p,'_probe',return_value={'ok':False}) as probe:
            self.assertFalse(p.probe(self.g,'1.1.1.1',self.s)['ok'])
        self.assertEqual(probe.call_count,3)

    def test_environment_failure_never_quarantines(self):
        result={'ip':'1.1.1.1','ok':False,'environment_error':True,'error':'missing engine'}
        with patch.object(p,'_probe',return_value=result) as probe:
            p.record_probe(self.g,p.probe(self.g,'1.1.1.1',self.s))
        self.assertEqual(probe.call_count,1)
        self.assertIn('1.1.1.1',p.active_ips(self.g))

    def test_missing_engine_is_environment_failure(self):
        with patch.object(p.shutil,'which',return_value=None):
            result=p.probe(self.g,'1.1.1.1',self.s)
        self.assertTrue(result['environment_error']);self.assertEqual(result['attempts'],1)

    def test_recovery_backoff_caps_and_resets_after_success(self):
        result={'ip':'2.2.2.2','ok':False}
        for delay in [300,1800,7200,86400,86400]:
            before=time.time();p.record_probe(self.g,result)
            self.assertAlmostEqual(self.g['failed_ips']['2.2.2.2']['next_retry']-before,delay,delta=2)
        self.g['failed_ips']['2.2.2.2']['next_retry']=0
        with patch.object(p,'probe',return_value={'ok':True}):p.recover_failed(self.g,self.s)
        p.record_probe(self.g,result)
        self.assertEqual(self.g['failed_ips']['2.2.2.2']['retry_level'],0)

    def test_other_domain_runs_while_first_domain_is_busy(self):
        p.put(self.g)
        p.put(dict(self.g,id='second',domain='second.example.com'))
        started=threading.Event();release=threading.Event();second=threading.Event()
        def slow(g,s,write):
            if g['id']=='test':started.set();release.wait(3)
            else:second.set()
        try:
            with patch.object(p,'rotate',side_effect=slow):
                self.assertTrue(p.run(['test']))
                self.assertTrue(started.wait(1))
                self.assertFalse(p.run(['test']))
                self.assertTrue(p.run(['second']))
                self.assertTrue(second.wait(1))
                self.assertFalse(p.RUNNING.acquire(blocking=False))
                release.set()
                self.assertTrue(p.RUNNING.acquire(timeout=3));p.RUNNING.release()
        finally:release.set()

    def test_environment_health_error_preserves_dns_and_pool(self):
        self.g.update(next_run=time.time()+3600,next_check=0);p.put(self.g)
        with patch.object(p,'probe',return_value={'ok':False,'environment_error':True,'error':'engine unavailable'}),patch.object(p,'rotate') as rotate:
            self.assertTrue(p.run(scheduled=True))
            self.assertTrue(p.RUNNING.acquire(timeout=3));p.RUNNING.release()
            rotate.assert_not_called()
        saved=p.groups()[0]
        self.assertEqual(saved['current'],'1.1.1.1');self.assertEqual(p.active_ips(saved),self.g['ips'])

    def test_force_recovery_checks_entire_pool_before_due(self):
        for ip in self.g['ips']:p.record_probe(self.g,{'ip':ip,'ok':False})
        settings=dict(self.s,workers=1)
        with patch.object(p,'probe',return_value={'ok':True}) as probe,patch.object(p.Cloudflare,'update') as update:
            p.recover_failed(self.g,settings,force=True)
        self.assertEqual(probe.call_count,3)
        self.assertEqual(self.g['failed_ips'],{})
        update.assert_not_called()

    def test_recovery_only_task_never_rotates(self):
        p.record_probe(self.g,{'ip':'2.2.2.2','ok':False});p.put(self.g)
        with patch.object(p,'probe',return_value={'ok':True}),patch.object(p,'rotate') as rotate:
            self.assertTrue(p.run(['test'],write=False,recovery_only=True))
            self.assertTrue(p.RUNNING.acquire(timeout=3));p.RUNNING.release()
            rotate.assert_not_called()
        self.assertEqual(p.groups()[0]['failed_ips'],{})

    def test_reject_mixed_family_pool(self):
        d=dict(self.g,ips=['1.1.1.1','::1'])
        with self.assertRaises(ValueError):p.validate_group(d)

if __name__=='__main__':unittest.main()
