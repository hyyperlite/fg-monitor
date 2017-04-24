#!/usr/bin/ruby

### Script for gathering diag and performance metrics from FortiGate

require 'net/ssh'
require 'trollop'
require 'json'

opts = Trollop::options do
  version 'fg-diag-all v0.1 - 2017 Carrier CSE'
  banner <<-EOS

fg-diag-all -  a flexible multi-use tool for monitoring FG via CLI commands. Many commands useful for tracking
during troubleshooting and performance testing are not available via API or methods other than CLI.  Results can
be formatted in json, csv, tsv or for consumption by Cacti.  Results can be output to stdout and/or a file.
Additionally, a logfile can be enabled where results are output in a more human readable format and errors may
also be sent to this file for troubleshooting.

Usage:
        fg-diag-np6-dce.rb [options]

where [options] are:
  EOS

  opt :host, 'Fortigate IP', :default => '192.168.1.1'
  opt :user, 'FortiGate Login Username', :default => 'admin'
  opt :pass, 'FortiGate Login Password', :default => ''
  opt :vdom, 'Specify this flag if FortiGate is in VDOM mode', :default => 'none'
  opt :npstart, 'For queries of NP data, enter the first NP to query (first would be np zero)', :default => 0
  opt :npstop, 'For queries of NP data, enter the last NP to query for', :default => 0
  opt :format, 'Output format for outfile and STDOUT. Options are: cacti, json, json-pretty, csv, tsv', :default => 'cacti'
  opt :outfile, 'To output result to file, specify the path/to/file', :type => :string
  opt :nostdout, 'By default results are sent to stdout, set this to disable'
  opt :perfstat, 'Summarized get sys perf stat (output only to log file, requires --logfile to be set)'
  opt :arpcount, 'Count number of arp entries and output'
  opt :hwnicfilter, "Set to enable: output to filter for from diag hardware deviceinfo nic <port>", :type => :string
  opt :niclist, "If setting hwnicfilter then also set nics to query i.e. \"port27 port29 port30\"", :type => :string
  opt :dcefilter, 'Filter for NP DCE counters (if no filter, dce will be skipped)', :type => :string
  opt :hrxfilter, 'Filter for NP HRX counters (if not filter, hrx will be skipped', :type => :string
  opt :adropfilter, 'Filter for NP anomaly drop counters (if no filter anaomoly drops will be skipped', :type => :string
  opt :logfile, 'path/to/logfile, no log file if not specified', :type => :string
  opt :debug, 'Enable additional console output (will break cacti processing)'
end

### Argument Checks

# Ensure output format entered is valid
unless opts[:format].downcase =~ /^(cacti|json|json-pretty|csv|tsv)$/
  Trollop::die :format, ': format must be one of "cacti json json-pretty csv tsv"'
end

# Ensure that if --hwnicfilter was provided, --niclist must also be
if opts[:hwnicfilter]
Trollop::die :niclist, ': --niclist option should be set if using --hwnicfilter option' unless opts[:niclist]
end

# To avoid troubleshooting later, if --perf
if opts[:perfstat]
  Trollop::die :logfile, ': --perfstats is enabled but perfstats only outputs to log file, please also set\
 --logfile option' unless opts[:logfile]
end


### script variables
debug = opts[:debug]
output = String.new
counterdata = Hash.new
dcedata = Hash.new
hrxdata = Hash.new
adropdata = Hash.new
nicdata = Hash.new
nic = Array.new
arpcount = Hash.new

###########################################################################
### Methods
###########################################################################
def get_sys_perf_stat(ssh, vdom, debug)
  cpu = 'CPU IDLE: '
  mem = 'MEM USED: '
  con = 'SESSIONS: '
  cps = 'CPS: '

  if vdom == 'none'
    r = ssh.exec!('get system performance status')
  else
    r = ssh.exec!("config global\n get system performance status")
  end
  r.downcase!

  # Process each line and extract consumable data
  r.each_line do |x|
    rec = x.split

    ### Check for obvious errors due to cmds sent to FG
    check_fgcmd_error(rec, 'perfstat', debug)

    rec.each_with_index do |element, index|
      #if filter.any? { |s| element.include? s}
        if element.include? 'cpu'
          if element == 'cpu'
            ### Treat this one seperate as it is system wide averge utilization
            cpu += "system:#{rec[index+10]} \n"
          else
            if element[3..-1].to_i < 10
              cpu += "#{element}:#{rec[index+10]} \t"
            else
              cpu += "#{element}:#{rec[index+10]}\t"
            end

            ### Add newline after every 8 CPUS
            cpu += "\n" if (element[3..-1].to_i + 1) % 8 == 0 unless element == 'cpu0'
          end
        end
        if element.include? 'mem'
          mem += "#{rec[index+2]}\n"
        end
        if element.include?('average') && rec[index+1].include?('sessions:')
          con += "1min:#{rec[index+2]} 10min:#{rec[index+7]} 30min:#{rec[index+12]}\n"
        end
        if element.include?('average') && rec[index+1] == 'session'
          cps += "1min:#{rec[index+4]} 10min:#{index+12} 30min:#{rec[index+20]}\n"
        end
      #end
    end
  end
  cpu += "\n"
  cpu + mem + con + cps + "\n"
end

def get_hardware_nic_info(filter, iface, ssh, vdom)
  if vdom == 'none'
    r = ssh.exec!("diagnose hardware deviceinfo nic #{iface}")
  else
    r = ssh.exec!("config global\n diagnose hardware deviceinfo nic #{iface}")
  end

  r.downcase!
end

def get_arp_count(ssh, vdom, debug)
  arpcount = Hash.new

  if vdom == 'none'
    r = ssh.exec!("diag ip arp list")
  else
    r = ssh.exec!("config vdom\n edit #{vdom}\n diag ip arp list")
  end

 ##TODO Add output checks (may want to modify existing with regex and then use for this, but will require modifying all)

  arpcount['arpcount'] = r.lines.count.to_s
  arpcount
end

def get_dce_counters(np, vdom, ssh)
  ### Execute diag npu np6 dce-all <np>
  if vdom == 'none'
    r = ssh.exec!("diag npu np6 dce-all #{np}")
  else
    r = ssh.exec!("config global\n diag npu np6 dce-all #{np}")
  end
  r.downcase
end

def get_hrx_counters(np, vdom, ssh)
  ### Execute diag npu np6 dce-all <np>
  if vdom == 'none'
    r = ssh.exec!("diag npu np6 hrx-drop-all #{np}")
  else
    r = ssh.exec!("config global\n diag npu np6 hrx-drop-all #{np}")
  end
  r.downcase
end

def get_adrop_counters(np, vdom, ssh)
  ### Execute diag npu np6 dce-all <np>
  if vdom == 'none'
    r = ssh.exec!("diag npu np6 anomaly-drop-all #{np}")
  else
    r = ssh.exec!("config global\n diag npu np6 anomaly-drop-all #{np}")
  end
  r.downcase
end

def process_counters(r, filter, id, logfile, opts, type)
  ### Process counter results passed in as r, apply filter and return hash
  counters = Hash.new

  ### Process each line and extract counters
  r.each_line do |x|

    ### Split the line by whitespace into an array "rec"
    rec = x.split

    ### Check for errors from FG due to command or vdom mode
    check_fgcmd_error(rec, type, opts)

    ### For each element from the current line find "interesting" counters (as determined in the if statement)
    ### and add to hash "counters"
    rec.each_with_index do |element, index|
      if filter.any? { |s| element.include? s }
        counters["np#{id}-#{element}"] = "#{rec[index+1][1..-1].to_i.to_s}" unless type == 'nic'

        ### The sw_out_drop_pkts does not have spaces so doesn't get split properly initially
        ### have to make a special exception for that one counter from diag hw devinfo nic
        if type == 'nic' && element.include?('sw_out_drop_pkts')
          tmp = element.split(':')
          counters["#{id}-#{tmp[0]}"] = "#{tmp[1].to_i.to_s}"
        elsif type == 'nic'
          counters["#{id}-#{element}"] = "#{rec[index+1][1..-1].to_i.to_s}"
        end
      end
    end
  end
  logfile.write "np#{id}-#{type}: #{counters.to_json}\n" if opts[:logfile] && type != 'nic'
  logfile.write "#{id}: #{counters.to_json}\n" if opts[:logfile] && type == 'nic'
  counters
end

def check_fgcmd_error(rec, type, opts)
  ### Check for error with commands sent to FG (usually due to vdom/non-vdom mode)
  i = 0
  while i <= 2  # Only need to look at first few lines to identify this issue
    rec.each do |element|
      if element.include?('Unknown')
        puts "FGCMDERROR: Unknown Action - while processing: #{type}"
        logfile.write "FGCMDERROR: Unknown Action - while processing #{type}\n" if opts[:logfile]
        exit 1
      end
    end
    i += 1
  end
end

###########################################################################
### Start Main
###########################################################################
begin
  logfile = File.open(opts[:logfile], 'a+') if opts[:logfile]
rescue
  puts "EXCEPTION: Failed to open logfile #{opts[:logfile]}\n"
  exit 1
end

begin
  ssh = Net::SSH.start(opts[:host], opts[:user], :password => opts[:pass],:timeout => 2)
rescue SocketError => e
  puts 'SOCKET ERROR: '+e.message
  logfile.write 'SOCKET ERROR: '+e.message+"\n" if opts[:logfile]
  exit 1
rescue Net::SSH::AuthenticationFailed
  puts 'AUTH ERROR: '+e.message
  logfile.write 'AUTH ERROR: '+e.message+"\n" if opts[:logfile]
  exit 1
rescue Exception => e
  puts 'EXCEPTION: '+e.message
  logfile.write 'EXCEPTION: '+e.message+"\n" if opts[:logfile]
  exit 1
end

logfile.write "--------#{Time.now}--------\n"

### Get system performance stats for log file only (not for output to other systems/csv)
if opts[:perfstat]
  perfdata = get_sys_perf_stat(ssh, opts[:vdom], debug)
  logfile.write perfdata if opts[:logfile]
end

### Get total arp entries from FG
if opts[:arpcount]
  arpcount = get_arp_count(ssh, opts[:vdom], debug)
  logfile.write "ARP Count: #{arpcount['arpcount']}\n\n" if opts[:logfile]
end

### Get diag hardware device info stats
if opts[:hwnicfilter] && opts[:niclist]
  nic = opts[:niclist].downcase.split
  filter = opts[:hwnicfilter].downcase.split(" ")
  nic.each do |x|
    result = get_hardware_nic_info(filter, x, ssh, opts[:vdom])
    puts "NICRESULT: #{result}" if debug

    nicdata.merge!(process_counters(result, filter, x, logfile, opts, 'nic'))
    puts "NICDATA: #{nicdata}" if debug
  end
end

if opts[:dcefilter] || opts[:hrxfilter] || opts[:adropfilter]
  ### Some stats are available only on per-np basis, we will loop through
  ### and execute such commands in this loop

  ### Call function to to get DCE counters and return formatted
  for np in opts[:npstart]..opts[:npstop]
    if opts[:dcefilter]
      filter = opts[:dcefilter].downcase.split

      ### Call method to retrieve DCE counters from FG
      result = get_dce_counters(np, opts[:vdom], ssh)
      puts "DCERESULT: #{result}" if debug

      ### Call method to process, filter and add counter key/value pairs (returns hash)
      dcedata.merge!(process_counters(result, filter, np, logfile, opts, 'dce'))
      puts "DCEDATA: #{dcedata}" if debug
    end
  end

  ### Call function to to get HRX counters and return formatted
  for np in opts[:npstart]..opts[:npstop]
    if opts[:hrxfilter]
      filter = opts[:hrxfilter].downcase.split

      ### Call method to retrieve HRX counters from FG
      result = get_hrx_counters(np, opts[:vdom], ssh)
      puts "HRXRESULT: #{result}" if debug

      ### Call method to process, filter and add counter key/value pairs (returns hash)
      hrxdata.merge!(process_counters(result, filter, np, logfile, opts, 'hrx'))
      puts "HRXDATA: #{dcedata}" if debug
    end
  end

  ### Call function to to get Anomaly Drop counters and return formatted
  for np in opts[:npstart]..opts[:npstop]
    if opts[:adropfilter]
      filter = opts[:adropfilter].downcase.split

      ### Call method to retrieve HRX counters from FG
      result = get_adrop_counters(np, opts[:vdom], ssh)
      puts "ADROPRESULT: #{result}" if debug

      ### Call method to process, filter and add counter key/value pairs (returns hash)
      adropdata.merge!(process_counters(result, filter, np, logfile, opts, 'adrop'))
      puts "ADROPDATA: #{dcedata}" if debug
    end
  end
end



#########################################################
### OUTPUT
#########################################################

### Create counter data in JSON output format
if opts[:format] == 'json' || opts[:format] == 'json-pretty'
  counterdata = {:date-time => Time.now}
  if dcedata.count > 0
    counterdata.store :dce, Hash.new
    dcedata.each do |key,val|
      counterdata[:dce].store key, val
    end
  end
  if hrxdata.count > 0
    counterdata.store :hrx_drop, Hash.new
    hrxdata.each do |key,val|
      counterdata[:hrx_drop].store key, val
    end
  end
  if adropdata.count > 0
    counterdata.store :anomaly_drop, Hash.new
    adropdata.each do |key,val|
      counterdata[:anomaly_drop].store key, val
    end
  end

  if nicdata.count > 0
    counterdata.store :interface, Hash.new
    nicdata.each do |key,val|
      counterdata[:interface].store key, val
    end
  end

  if arpcount.count > 0
    counterdata[:arpcount] = arpcount
  end

  output = counterdata.to_json if opts[:format] == 'json'
  output = JSON.pretty_generate(counterdata) if opts[:format] == 'json-pretty'

else ### For all other data output formats

### Merge all hashes into single hash for output
  counterdata.merge!(dcedata)
  counterdata.merge!(hrxdata)
  counterdata.merge!(adropdata)
  counterdata.merge!(nicdata)
  counterdata.merge!(arpcount)

### Create counter data in CACTI output format
  if counterdata.count > 0 && opts[:format] == 'cacti'
    counterdata.each do |key, val|
      output += "#{key}:#{val} "
    end
  end

### Create counter data in CSV output format
# Only values will be output in CSV so one
# will need to know the order.  Order should
# remain consistent and is determined by order
# received from FortiGate
# (may add additional functionality to query order separate)
  if counterdata.count > 0 && opts[:format] == 'csv'
    counterdata.each do |key, val|
      output += "#{val},"
    end
  end

### Create counter data in TSV output format
# Only values will be output in TSV so one
# will need to know the order.  Order should
# remain consistent and is determined by order
# received from FortiGate
# (may add additional functionality to query order separate)
  if counterdata.count > 0 && opts[:format] == 'tsv'
    counterdata.each do |key, val|
      output += "#{val}\t"
    end
  end
end

### Write results to STDOUT
#puts output unless opts[:nostdout]
puts output

if opts[:outfile]
  begin
    File.open(opts[:outfile], 'a+') do |f|
      f.write "#{output}\n"
    end
  rescue
    puts "EXCEPTION: Failed to open outfile #{opts[:outfile]}"
    exit 1
  end
end

### Cleanup ###
ssh.close
logfile.write "\n"
logfile.close