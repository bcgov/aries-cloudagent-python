# Setup
You need a postgres server running locally. Outside of the docker network, because the urls used are pointing to localhost via docker internal urls.

You need to make two users
local-cloud-agent
admin-cloud-agent

Password: testtest

Then you should be ready to run docker compose

Run the webhook-receiver to see the webhooks

# Run the docker
In one terminal: `docker-compose -p agent up`
In another one: `docker-compose -p admin -f docker-compose-admin.yaml --env-file .admin.env up`

# Run the actions
The admin is hosted on `localhost:5001`    
Use two windows, make two multitenant wallets.    
Authenticate them with the token returned    

Create a invitation to connection in one window.    
Recieve the connection in the other.     
I believe the system is missing a webhook here?     

Accept the request in the same window, and see the crash.

In terminal for just agent, you will see some strange errors

<details>
  <summary>Error on the receiving agent</summary>

    ```
    diwala-agent_1  | 2021-03-04 14:45:54,825 indy.non_secrets DEBUG open_wallet_search: >>> wallet_handle: 2, type_: 'forward_route', query_json: '{"recipient_key": "GVfXa1sMi4mXUZbwq9ZUjUYZYgV5EsAJxuCFVKCmaFWu"}', options_json: '{"retrieveRecords": true, "retrieveTotalCount": false, "retrieveType": false, "retrieveValue": true, "retrieveTags": false}'
    diwala-agent_1  | 2021-03-04 14:45:54,826 indy.libindy DEBUG do_call: >>> name: indy_open_wallet_search, args: (c_int(2), c_char_p(139902117971776), c_char_p(139902117853192), c_char_p(139902132838224), <CFunctionType object at 0x7f3d800b2110>)
    diwala-agent_1  | 2021-03-04 14:45:54,827 indy.libindy DEBUG do_call: Function indy_open_wallet_search returned err: 0
    diwala-agent_1  | 2021-03-04 14:45:54,827 indy.libindy.native.postgres DEBUG 	/home/indy/.cargo/registry/src/github.com-1ecc6299db9ec823/postgres-0.15.2/src/lib.rs:901 | executing query:
    diwala-agent_1  | 2021-03-04 14:45:54,827 indy.libindy DEBUG do_call: <<< <Future pending>
    diwala-agent_1  | 2021-03-04 14:45:54,829 indy.libindy.native.postgres DEBUG 	/home/indy/.cargo/registry/src/github.com-1ecc6299db9ec823/postgres-0.15.2/src/lib.rs:901 | executing query:
    diwala-agent_1  | 2021-03-04 14:45:54,830 indy.libindy.native.postgres DEBUG 	/home/indy/.cargo/registry/src/github.com-1ecc6299db9ec823/postgres-0.15.2/src/lib.rs:489 | preparing query with name `s1`: WITH tags_encrypted as (select * from tags_encrypted where wallet_id = $5) SELECT i.id, i.name, i.value, i.key, i.type FROM items as i WHERE i.type = $1 AND (i.id in (SELECT item_id FROM tags_encrypted WHERE name = $2 AND value = $3)) AND i.wallet_id = $4
    diwala-agent_1  | 2021-03-04 14:45:54,832 indy.libindy.native.postgres DEBUG 	/home/indy/.cargo/registry/src/github.com-1ecc6299db9ec823/postgres-0.15.2/src/lib.rs:608 | executing statement s1 with parameters: [[99, 73, 98, 105, 71, 109, 81, 88, 68, 50, 72, 113, 49, 117, 102, 111, 103, 101, 65, 57, 121, 103, 53, 108, 88, 50, 109, 97, 118, 48, 112, 73, 102, 98, 66, 75, 89, 88, 97, 76, 90, 49, 122, 98, 84, 86, 49, 100, 122, 105, 107, 71, 80, 55, 48, 61], [128, 95, 201, 87, 31, 135, 103, 34, 61, 79, 91, 92, 68, 248, 118, 10, 102, 38, 192, 122, 135, 212, 187, 11, 193, 153, 206, 83, 84, 211, 60, 6, 239, 112, 28, 111, 31, 109, 154, 182, 253], [8, 163, 57, 149, 158, 156, 119, 109, 99, 95, 89, 199, 130, 47, 53, 202, 252, 2, 17, 5, 172, 218, 209, 236, 51, 45, 146, 119, 129, 138, 30, 90, 131, 102, 72, 140, 61, 83, 213, 109, 81, 216, 220, 75, 40, 120, 25, 120, 17, 70, 99, 45, 182, 177, 232, 138, 112, 29, 81, 133, 146, 62, 55, 198, 72, 169, 135, 185, 88, 247, 182, 189], "diwala2", "diwala2"]
    diwala-agent_1  | 2021-03-04 14:45:54,834 indy.libindy DEBUG _indy_callback: >>> command_handle: 77, err , args: (22,)
    diwala-agent_1  | 2021-03-04 14:45:54,834 indy.libindy DEBUG _indy_callback: <<<
    diwala-agent_1  | 2021-03-04 14:45:54,834 indy.libindy DEBUG _indy_loop_callback: >>> command_handle: 77, err , args: (22,)
    diwala-agent_1  | 2021-03-04 14:45:54,835 indy.libindy DEBUG _indy_loop_callback: Function returned 22
    diwala-agent_1  | 2021-03-04 14:45:54,835 indy.libindy DEBUG _indy_loop_callback <<<
    diwala-agent_1  | 2021-03-04 14:45:54,835 indy.non_secrets DEBUG open_wallet_search: <<< res: 22
    diwala-agent_1  | 2021-03-04 14:45:54,835 indy.non_secrets DEBUG fetch_wallet_search_next_records: >>> wallet_handle: 2, wallet_search_handle: 22, count: 100
    diwala-agent_1  | 2021-03-04 14:45:54,836 indy.libindy DEBUG do_call: >>> name: indy_fetch_wallet_search_next_records, args: (c_int(2), c_int(22), c_uint(100), <CFunctionType object at 0x7f3d800b22a0>)
    diwala-agent_1  | 2021-03-04 14:45:54,836 indy.libindy DEBUG do_call: Function indy_fetch_wallet_search_next_records returned err: 0
    diwala-agent_1  | 2021-03-04 14:45:54,836 indy.libindy DEBUG _indy_callback: >>> command_handle: 78, err , args: (b'{"totalCount":null,"records":[{"type":null,"id":"57a90432-b265-432e-b0e5-fe9ddc73881b","value":"{\\"wallet_id\\": \\"c71985ee-5715-459d-8d00-cde3d8459aea\\", \\"recipient_key\\": \\"GVfXa1sMi4mXUZbwq9ZUjUYZYgV5EsAJxuCFVKCmaFWu\\", \\"role\\": \\"server\\", \\"created_at\\": \\"2021-03-04 14:18:48.165574Z\\", \\"updated_at\\": \\"2021-03-04 14:18:48.165574Z\\", \\"connection_id\\": null}","tags":null}]}',)
    diwala-agent_1  | 2021-03-04 14:45:54,837 indy.libindy DEBUG _indy_callback: <<<
    diwala-agent_1  | 2021-03-04 14:45:54,836 indy.libindy DEBUG do_call: <<< <Future pending>
    diwala-agent_1  | 2021-03-04 14:45:54,838 indy.libindy DEBUG _indy_loop_callback: >>> command_handle: 78, err , args: (b'{"totalCount":null,"records":[{"type":null,"id":"57a90432-b265-432e-b0e5-fe9ddc73881b","value":"{\\"wallet_id\\": \\"c71985ee-5715-459d-8d00-cde3d8459aea\\", \\"recipient_key\\": \\"GVfXa1sMi4mXUZbwq9ZUjUYZYgV5EsAJxuCFVKCmaFWu\\", \\"role\\": \\"server\\", \\"created_at\\": \\"2021-03-04 14:18:48.165574Z\\", \\"updated_at\\": \\"2021-03-04 14:18:48.165574Z\\", \\"connection_id\\": null}","tags":null}]}',)
    diwala-agent_1  | 2021-03-04 14:45:54,838 indy.libindy DEBUG _indy_loop_callback: Function returned b'{"totalCount":null,"records":[{"type":null,"id":"57a90432-b265-432e-b0e5-fe9ddc73881b","value":"{\\"wallet_id\\": \\"c71985ee-5715-459d-8d00-cde3d8459aea\\", \\"recipient_key\\": \\"GVfXa1sMi4mXUZbwq9ZUjUYZYgV5EsAJxuCFVKCmaFWu\\", \\"role\\": \\"server\\", \\"created_at\\": \\"2021-03-04 14:18:48.165574Z\\", \\"updated_at\\": \\"2021-03-04 14:18:48.165574Z\\", \\"connection_id\\": null}","tags":null}]}'
    diwala-agent_1  | 2021-03-04 14:45:54,838 indy.libindy DEBUG _indy_loop_callback <<<
    diwala-agent_1  | 2021-03-04 14:45:54,839 indy.non_secrets DEBUG fetch_wallet_search_next_records: <<< res: '{"totalCount":null,"records":[{"type":null,"id":"57a90432-b265-432e-b0e5-fe9ddc73881b","value":"{\\"wallet_id\\": \\"c71985ee-5715-459d-8d00-cde3d8459aea\\", \\"recipient_key\\": \\"GVfXa1sMi4mXUZbwq9ZUjUYZYgV5EsAJxuCFVKCmaFWu\\", \\"role\\": \\"server\\", \\"created_at\\": \\"2021-03-04 14:18:48.165574Z\\", \\"updated_at\\": \\"2021-03-04 14:18:48.165574Z\\", \\"connection_id\\": null}","tags":null}]}'
    diwala-agent_1  | 2021-03-04 14:45:54,840 indy.non_secrets DEBUG fetch_wallet_search_next_records: >>> wallet_handle: 2, wallet_search_handle: 22, count: 100
    diwala-agent_1  | 2021-03-04 14:45:54,840 indy.libindy DEBUG do_call: >>> name: indy_fetch_wallet_search_next_records, args: (c_int(2), c_int(22), c_uint(100), <CFunctionType object at 0x7f3d800b22a0>)
    diwala-agent_1  | 2021-03-04 14:45:54,840 indy.libindy DEBUG do_call: Function indy_fetch_wallet_search_next_records returned err: 0
    diwala-agent_1  | 2021-03-04 14:45:54,841 indy.libindy DEBUG _indy_callback: >>> command_handle: 79, err , args: (b'{"totalCount":null,"records":null}',)
    diwala-agent_1  | 2021-03-04 14:45:54,841 indy.libindy DEBUG do_call: <<< <Future pending>
    diwala-agent_1  | 2021-03-04 14:45:54,841 indy.libindy DEBUG _indy_callback: <<<
    diwala-agent_1  | 2021-03-04 14:45:54,842 indy.libindy DEBUG _indy_loop_callback: >>> command_handle: 79, err , args: (b'{"totalCount":null,"records":null}',)
    diwala-agent_1  | 2021-03-04 14:45:54,843 indy.libindy DEBUG _indy_loop_callback: Function returned b'{"totalCount":null,"records":null}'
    diwala-agent_1  | 2021-03-04 14:45:54,843 indy.libindy DEBUG _indy_loop_callback <<<
    diwala-agent_1  | 2021-03-04 14:45:54,844 indy.non_secrets DEBUG fetch_wallet_search_next_records: <<< res: '{"totalCount":null,"records":null}'
    diwala-agent_1  | 2021-03-04 14:45:54,844 indy.non_secrets DEBUG close_wallet_search: >>> wallet_search_handle: 22
    diwala-agent_1  | 2021-03-04 14:45:54,845 indy.libindy DEBUG do_call: >>> name: indy_close_wallet_search, args: (c_int(22), <CFunctionType object at 0x7f3d800b24f8>)
    diwala-agent_1  | 2021-03-04 14:45:54,845 indy.libindy DEBUG do_call: Function indy_close_wallet_search returned err: 0
    diwala-agent_1  | 2021-03-04 14:45:54,846 indy.libindy DEBUG _indy_callback: >>> command_handle: 80, err , args: ()
    diwala-agent_1  | 2021-03-04 14:45:54,846 indy.libindy DEBUG do_call: <<< <Future pending>
    diwala-agent_1  | 2021-03-04 14:45:54,847 indy.libindy DEBUG _indy_callback: <<<
    diwala-agent_1  | 2021-03-04 14:45:54,848 indy.libindy DEBUG _indy_loop_callback: >>> command_handle: 80, err , args: ()
    diwala-agent_1  | 2021-03-04 14:45:54,848 indy.libindy DEBUG _indy_loop_callback: Function returned None
    diwala-agent_1  | 2021-03-04 14:45:54,849 indy.libindy DEBUG _indy_loop_callback <<<
    diwala-agent_1  | 2021-03-04 14:45:54,850 indy.non_secrets DEBUG close_wallet_search: <<< res: None
    diwala-agent_1  | 2021-03-04 14:45:54,851 indy.non_secrets DEBUG get_wallet_record: >>> wallet_handle: 2, type_: 'wallet_record', id: 'c71985ee-5715-459d-8d00-cde3d8459aea', options_json: '{"retrieveType": false, "retrieveValue": true, "retrieveTags": false}'
    diwala-agent_1  | 2021-03-04 14:45:54,851 indy.libindy DEBUG do_call: >>> name: indy_get_wallet_record, args: (c_int(2), c_char_p(139902117970144), c_char_p(139902117869616), c_char_p(139902117853400), <CFunctionType object at 0x7f3d800dd2a0>)
    diwala-agent_1  | 2021-03-04 14:45:54,851 indy.libindy DEBUG do_call: Function indy_get_wallet_record returned err: 0
    diwala-agent_1  | 2021-03-04 14:45:54,852 indy.libindy DEBUG do_call: <<< <Future pending>
    diwala-agent_1  | 2021-03-04 14:45:54,852 indy.libindy.native.postgres DEBUG 	/home/indy/.cargo/registry/src/github.com-1ecc6299db9ec823/postgres-0.15.2/src/lib.rs:901 | executing query:
    diwala-agent_1  | 2021-03-04 14:45:54,855 indy.libindy.native.postgres DEBUG 	/home/indy/.cargo/registry/src/github.com-1ecc6299db9ec823/postgres-0.15.2/src/lib.rs:489 | preparing query with name ``: SELECT id, value, key FROM items where type = $1 AND name = $2 AND wallet_id = $3
    diwala-agent_1  | 2021-03-04 14:45:54,857 indy.libindy.native.postgres DEBUG 	/home/indy/.cargo/registry/src/github.com-1ecc6299db9ec823/postgres-0.15.2/src/lib.rs:608 | executing statement  with parameters: [[119, 80, 110, 120, 97, 115, 81, 66, 103, 83, 51, 89, 54, 52, 110, 57, 83, 100, 82, 87, 87, 117, 100, 75, 51, 114, 57, 52, 57, 103, 105, 98, 104, 49, 85, 99, 108, 111, 113, 47, 43, 77, 105, 81, 53, 116, 54, 49, 107, 76, 75, 48, 116, 75, 81, 61], [111, 50, 74, 79, 97, 52, 98, 111, 53, 80, 99, 100, 81, 114, 66, 66, 82, 109, 67, 90, 111, 109, 77, 121, 115, 117, 81, 89, 67, 79, 50, 48, 97, 121, 122, 109, 74, 121, 90, 114, 114, 54, 73, 112, 90, 81, 108, 118, 77, 65, 68, 109, 113, 67, 67, 56, 51, 105, 67, 112, 100, 121, 56, 71, 122, 107, 83, 81, 57, 88, 120, 65, 114, 114, 109, 118, 119, 74, 114, 74, 71, 118, 85, 77, 100, 81, 61, 61], "diwala2"]
    diwala-agent_1  | 2021-03-04 14:45:54,858 indy.libindy DEBUG _indy_callback: >>> command_handle: 81, err , args: (b'{"type":null,"id":"c71985ee-5715-459d-8d00-cde3d8459aea","value":"{\\"wallet_name\\": \\"BobWallet\\", \\"created_at\\": \\"2021-03-04 14:16:21.437242Z\\", \\"updated_at\\": \\"2021-03-04 14:16:21.437242Z\\", \\"settings\\": {\\"wallet.type\\": \\"indy\\", \\"wallet.name\\": \\"BobWallet\\", \\"wallet.key\\": \\"MySecretKey123\\", \\"wallet.webhook_urls\\": [\\"http://host.docker.internal:3000/webhooks\\"], \\"wallet.dispatch_type\\": \\"default\\", \\"default_label\\": \\"Bob\\", \\"image_url\\": \\"https://aries.ca/images/sample.png\\", \\"wallet.id\\": \\"c71985ee-5715-459d-8d00-cde3d8459aea\\"}, \\"key_management_mode\\": \\"managed\\"}","tags":null}',)
    diwala-agent_1  | 2021-03-04 14:45:54,858 indy.libindy DEBUG _indy_callback: <<<
    diwala-agent_1  | 2021-03-04 14:45:54,859 indy.libindy DEBUG _indy_loop_callback: >>> command_handle: 81, err , args: (b'{"type":null,"id":"c71985ee-5715-459d-8d00-cde3d8459aea","value":"{\\"wallet_name\\": \\"BobWallet\\", \\"created_at\\": \\"2021-03-04 14:16:21.437242Z\\", \\"updated_at\\": \\"2021-03-04 14:16:21.437242Z\\", \\"settings\\": {\\"wallet.type\\": \\"indy\\", \\"wallet.name\\": \\"BobWallet\\", \\"wallet.key\\": \\"MySecretKey123\\", \\"wallet.webhook_urls\\": [\\"http://host.docker.internal:3000/webhooks\\"], \\"wallet.dispatch_type\\": \\"default\\", \\"default_label\\": \\"Bob\\", \\"image_url\\": \\"https://aries.ca/images/sample.png\\", \\"wallet.id\\": \\"c71985ee-5715-459d-8d00-cde3d8459aea\\"}, \\"key_management_mode\\": \\"managed\\"}","tags":null}',)
    diwala-agent_1  | 2021-03-04 14:45:54,859 indy.libindy DEBUG _indy_loop_callback: Function returned b'{"type":null,"id":"c71985ee-5715-459d-8d00-cde3d8459aea","value":"{\\"wallet_name\\": \\"BobWallet\\", \\"created_at\\": \\"2021-03-04 14:16:21.437242Z\\", \\"updated_at\\": \\"2021-03-04 14:16:21.437242Z\\", \\"settings\\": {\\"wallet.type\\": \\"indy\\", \\"wallet.name\\": \\"BobWallet\\", \\"wallet.key\\": \\"MySecretKey123\\", \\"wallet.webhook_urls\\": [\\"http://host.docker.internal:3000/webhooks\\"], \\"wallet.dispatch_type\\": \\"default\\", \\"default_label\\": \\"Bob\\", \\"image_url\\": \\"https://aries.ca/images/sample.png\\", \\"wallet.id\\": \\"c71985ee-5715-459d-8d00-cde3d8459aea\\"}, \\"key_management_mode\\": \\"managed\\"}","tags":null}'
    diwala-agent_1  | 2021-03-04 14:45:54,860 indy.libindy DEBUG _indy_loop_callback <<<
    diwala-agent_1  | 2021-03-04 14:45:54,860 indy.non_secrets DEBUG get_wallet_record: <<< res: '{"type":null,"id":"c71985ee-5715-459d-8d00-cde3d8459aea","value":"{\\"wallet_name\\": \\"BobWallet\\", \\"created_at\\": \\"2021-03-04 14:16:21.437242Z\\", \\"updated_at\\": \\"2021-03-04 14:16:21.437242Z\\", \\"settings\\": {\\"wallet.type\\": \\"indy\\", \\"wallet.name\\": \\"BobWallet\\", \\"wallet.key\\": \\"MySecretKey123\\", \\"wallet.webhook_urls\\": [\\"http://host.docker.internal:3000/webhooks\\"], \\"wallet.dispatch_type\\": \\"default\\", \\"default_label\\": \\"Bob\\", \\"image_url\\": \\"https://aries.ca/images/sample.png\\", \\"wallet.id\\": \\"c71985ee-5715-459d-8d00-cde3d8459aea\\"}, \\"key_management_mode\\": \\"managed\\"}","tags":null}'
    diwala-agent_1  | 2021-03-04 14:45:54,862 aiohttp.server ERROR Error handling request
    diwala-agent_1  | Traceback (most recent call last):
    diwala-agent_1  |   File "/home/indy/.pyenv/versions/3.6.13/lib/python3.6/site-packages/aiohttp/web_protocol.py", line 418, in start
    diwala-agent_1  |     resp = await task
    diwala-agent_1  |   File "/home/indy/.pyenv/versions/3.6.13/lib/python3.6/site-packages/aiohttp/web_app.py", line 458, in _handle
    diwala-agent_1  |     resp = await handler(request)
    diwala-agent_1  |   File "/home/indy/.pyenv/versions/3.6.13/lib/python3.6/site-packages/aries_cloudagent/transport/inbound/http.py", line 96, in inbound_message_handler
    diwala-agent_1  |     inbound = await session.receive(body)
    diwala-agent_1  |   File "/home/indy/.pyenv/versions/3.6.13/lib/python3.6/site-packages/aries_cloudagent/transport/inbound/session.py", line 219, in receive
    diwala-agent_1  |     await self.handle_relay_context(payload_enc)
    diwala-agent_1  |   File "/home/indy/.pyenv/versions/3.6.13/lib/python3.6/site-packages/aries_cloudagent/transport/inbound/session.py", line 174, in handle_relay_context
    diwala-agent_1  |     base_responder: AdminResponder = profile.inject(BaseResponder)
    diwala-agent_1  |   File "/home/indy/.pyenv/versions/3.6.13/lib/python3.6/site-packages/aries_cloudagent/core/profile.py", line 94, in inject
    diwala-agent_1  |     return self._context.inject(base_cls, settings, required=required)
    diwala-agent_1  |   File "/home/indy/.pyenv/versions/3.6.13/lib/python3.6/site-packages/aries_cloudagent/config/injection_context.py", line 126, in inject
    diwala-agent_1  |     return self.injector.inject(base_cls, settings, required=required)
    diwala-agent_1  |   File "/home/indy/.pyenv/versions/3.6.13/lib/python3.6/site-packages/aries_cloudagent/config/injector.py", line 86, in inject
    diwala-agent_1  |     "No instance provided for class: {}".format(base_cls.__name__)
    diwala-agent_1  | aries_cloudagent.config.base.InjectionError: No instance provided for class: BaseResponder
    diwala-agent_1  | 2021-03-04 14:45:54,864 aiohttp.access INFO 172.25.0.1 [04/Mar/2021:14:45:54 +0000] "POST / HTTP/1.1" 500 244 "-" "Python/3.6 aiohttp/3.6.3"
    ```
</details>

<details>
  <summary>Error on the sending agent</summary>

```
diwala-admin-agent_1  | 2021-03-04 14:45:44,781 aries_cloudagent.transport.outbound.manager ERROR >>> Error when posting to: http://host.docker.internal:10000; Error: (<class 'aries_cloudagent.transport.outbound.base.OutboundTransportError'>, OutboundTransportError('Unexpected response status 500, caused by: Internal Server Error',), <traceback object at 0x7f3fb8d28b48>); Payload: b'{"protected":"eyJlbmMiOiJ4Y2hhY2hhMjBwb2x5MTMwNV9pZXRmIiwidHlwIjoiSldNLzEuMCIsImFsZyI6IkF1dGhjcnlwdCIsInJlY2lwaWVudHMiOlt7ImVuY3J5cHRlZF9rZXkiOiJxZ1VEMkVpN1UzcmhBOE1Yb0tQbXpreE9RSkdjaEFMekdjTHRLZ2NPdm0tMkFPaEpWNXM3bUk0UHFVbHVUMkFRIiwiaGVhZGVyIjp7ImtpZCI6IkdWZlhhMXNNaTRtWFVaYndxOVpValVZWllnVjVFc0FKeHVDRlZLQ21hRld1IiwiaXYiOiIySHZWREgwNExwTjVuUkhpdFJrc3c2Tmc0M2VjS0prVyIsInNlbmRlciI6InlxMUpmUGpVLTdtRUswT0RBOHJMVGJvTkdWVi1NLXE0akZxTWtmZmlzSFhtSzRZUXdHOGRwNVo5ZnI3dGMzaDBDRVJTazB5WHZTdXMyNmZnUWJsblNUY2dvREcyZk13dDdyeElMQlpBck1BX1g3QXpfUVNEeFh6aFhWbz0ifX1dfQ==","iv":"EP4H2-mngSsLBdrY","ciphertext":"RXzl_qzyZjNRc5sjPtffIVlbXwYCEEPJTz4tca2EHr1Aj2KtsxLMZzbSeDccrCpOsBx5380j_Iwy_VpKoVHl8CsWe_YA7aML7ywEeGqHIsl2m0THXkA0p-mt9vYTKiJbud3wBvc-hx0GKvw1gYpuZvMIMo9xiUEyRmqSiX68H5aLKiIkraRge9mbbYXjvy0RqjxltorxRVtXdYOpsatae1hzQPMVZJkcJiZe2GsGN4yFoCw96kpMwNDjWqsuf2hRlKciUVzEOH7Pcf8gA_cl3DRGXyXWmVtlkb-Saqx-V62G_9eOHBhwfojrFdGlY3WSktYkf4ACpmsBwN9xS173FCTB9YC3a8H9u2CbSLZMuH-sBJWWgOnLS4Gfn52Vh17TeE-BNks9bPsA4RUUk4ADJx3hk6m_eZPodJzEb1PUYrr6SHiC0OPH-UodwUyGCDDD019MdT8Lveuaw9UNAo9g2hlsOJfC1jw2t2i51PYP8p2OoM_YfQfHaSF9VvggOqtnDFC0ykXBICbrq5UCEwCbYoehzMyOxhUItnskKibmJWUjXMS8H2MqwHjxXyQbQZbbxdDItJLWB7zJSbZZBRhRI5K4TkY1u2428m-pVLNvjCvgcvmQqCwc0wmtX9ACaYNHTVsFiTG3q37ChNLUOv4gLgG9rauSFiuJME6xpMloBceILeNkWw4NWxBQE7Uys_EvYdmebXwy3ZG6d7wQOBHD4XjMId1l65vD4PoreyoHDbubNXJsFacd7578QN58E1gjl9_EBfxVXK8-TrVplo6BKlJNpNeSStnd0i7tkqZSCQNhdK8HZLFDsTv1LV2n-JfTLSxl-3wkLGsl3MHTPx71wNaIcEzZswEs08MU-If2d3iI4IukeKRh0k68tkAA1gQWZwux3VqEndW1Gr0zWdkygXwppIfxUfLpUybRcXG3ZYMbqo8y6wgBM7avFNq04OmPbXqAbSjuu3PNwnYPFkRov00f4O3nY9faLgqrGTbIPuIu3PRxNGDC2Tj-Ze0jNQIh7Dv-GRHt87NgXJ4QFHa7DEh5o8xTME8uLv67jpWgfWXX6l01pWW_G_sXd19etqTJL5wtF3pI8jHqFzBNAnQ7R34tQZ9PCu9WCIijUTcNVuSYvTC92xsgaj92IyefYgLaQrmUYt8MtHfuBT4=","tag":"YOh_pCy6_PHLeTIK4UX2Aw=="}'; Re-queue failed message ...
diwala-admin-agent_1  | 2021-03-04 14:45:54,815 aries_cloudagent.transport.outbound.http DEBUG Posting to http://host.docker.internal:10000; Data: b'{"protected":"eyJlbmMiOiJ4Y2hhY2hhMjBwb2x5MTMwNV9pZXRmIiwidHlwIjoiSldNLzEuMCIsImFsZyI6IkF1dGhjcnlwdCIsInJlY2lwaWVudHMiOlt7ImVuY3J5cHRlZF9rZXkiOiJxZ1VEMkVpN1UzcmhBOE1Yb0tQbXpreE9RSkdjaEFMekdjTHRLZ2NPdm0tMkFPaEpWNXM3bUk0UHFVbHVUMkFRIiwiaGVhZGVyIjp7ImtpZCI6IkdWZlhhMXNNaTRtWFVaYndxOVpValVZWllnVjVFc0FKeHVDRlZLQ21hRld1IiwiaXYiOiIySHZWREgwNExwTjVuUkhpdFJrc3c2Tmc0M2VjS0prVyIsInNlbmRlciI6InlxMUpmUGpVLTdtRUswT0RBOHJMVGJvTkdWVi1NLXE0akZxTWtmZmlzSFhtSzRZUXdHOGRwNVo5ZnI3dGMzaDBDRVJTazB5WHZTdXMyNmZnUWJsblNUY2dvREcyZk13dDdyeElMQlpBck1BX1g3QXpfUVNEeFh6aFhWbz0ifX1dfQ==","iv":"EP4H2-mngSsLBdrY","ciphertext":"RXzl_qzyZjNRc5sjPtffIVlbXwYCEEPJTz4tca2EHr1Aj2KtsxLMZzbSeDccrCpOsBx5380j_Iwy_VpKoVHl8CsWe_YA7aML7ywEeGqHIsl2m0THXkA0p-mt9vYTKiJbud3wBvc-hx0GKvw1gYpuZvMIMo9xiUEyRmqSiX68H5aLKiIkraRge9mbbYXjvy0RqjxltorxRVtXdYOpsatae1hzQPMVZJkcJiZe2GsGN4yFoCw96kpMwNDjWqsuf2hRlKciUVzEOH7Pcf8gA_cl3DRGXyXWmVtlkb-Saqx-V62G_9eOHBhwfojrFdGlY3WSktYkf4ACpmsBwN9xS173FCTB9YC3a8H9u2CbSLZMuH-sBJWWgOnLS4Gfn52Vh17TeE-BNks9bPsA4RUUk4ADJx3hk6m_eZPodJzEb1PUYrr6SHiC0OPH-UodwUyGCDDD019MdT8Lveuaw9UNAo9g2hlsOJfC1jw2t2i51PYP8p2OoM_YfQfHaSF9VvggOqtnDFC0ykXBICbrq5UCEwCbYoehzMyOxhUItnskKibmJWUjXMS8H2MqwHjxXyQbQZbbxdDItJLWB7zJSbZZBRhRI5K4TkY1u2428m-pVLNvjCvgcvmQqCwc0wmtX9ACaYNHTVsFiTG3q37ChNLUOv4gLgG9rauSFiuJME6xpMloBceILeNkWw4NWxBQE7Uys_EvYdmebXwy3ZG6d7wQOBHD4XjMId1l65vD4PoreyoHDbubNXJsFacd7578QN58E1gjl9_EBfxVXK8-TrVplo6BKlJNpNeSStnd0i7tkqZSCQNhdK8HZLFDsTv1LV2n-JfTLSxl-3wkLGsl3MHTPx71wNaIcEzZswEs08MU-If2d3iI4IukeKRh0k68tkAA1gQWZwux3VqEndW1Gr0zWdkygXwppIfxUfLpUybRcXG3ZYMbqo8y6wgBM7avFNq04OmPbXqAbSjuu3PNwnYPFkRov00f4O3nY9faLgqrGTbIPuIu3PRxNGDC2Tj-Ze0jNQIh7Dv-GRHt87NgXJ4QFHa7DEh5o8xTME8uLv67jpWgfWXX6l01pWW_G_sXd19etqTJL5wtF3pI8jHqFzBNAnQ7R34tQZ9PCu9WCIijUTcNVuSYvTC92xsgaj92IyefYgLaQrmUYt8MtHfuBT4=","tag":"YOh_pCy6_PHLeTIK4UX2Aw=="}'; Headers: {'Content-Type': 'application/ssi-agent-wire'}
diwala-admin-agent_1  | 2021-03-04 14:45:54,866 aries_cloudagent.transport.outbound.manager ERROR >>> Outbound message failed to deliver, NOT Re-queued.
diwala-admin-agent_1  | Traceback (most recent call last):
diwala-admin-agent_1  |   File "/home/indy/.pyenv/versions/3.6.13/lib/python3.6/site-packages/aries_cloudagent/transport/outbound/http.py", line 86, in handle_message
diwala-admin-agent_1  |     f"Unexpected response status {response.status}, "
diwala-admin-agent_1  | aries_cloudagent.transport.outbound.base.OutboundTransportError: Unexpected response status 500, caused by: Internal Server Error
diwala-admin-agent_1  | 2021-03-04 14:45:54,867 aries_cloudagent.transport.outbound.manager ERROR Outbound message could not be delivered to http://host.docker.internal:10000
diwala-admin-agent_1  | Traceback (most recent call last):
diwala-admin-agent_1  |   File "/home/indy/.pyenv/versions/3.6.13/lib/python3.6/site-packages/aries_cloudagent/transport/outbound/http.py", line 86, in handle_message
diwala-admin-agent_1  |     f"Unexpected response status {response.status}, "
diwala-admin-agent_1  | aries_cloudagent.transport.outbound.base.OutboundTransportError: Unexpected response status 500, caused by: Internal Server Error
```
</details>

The connection state never changes, and there is no clear pointer to what happens

