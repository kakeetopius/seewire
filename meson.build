project('seewire', 'c')

pcap_dep = dependency('pcap')
incdir = include_directories('include')

src_dir = 'src'
src_net_dir = 'net'
src_util_dir = 'util'

net_srcs = ['arp.c', 'datalink.c', 'dns.c', 'http.c', 'ip4.c', 'tcp.c', 'udp.c']
util_srcs = ['argparser.c', 'output_printer.c', 'pcap_wrapper.c']

srcs = ['src/main.c']

foreach src_file : net_srcs
  src_file = src_dir / src_net_dir / src_file
  srcs += src_file
endforeach

foreach src_file : util_srcs
  src_file = src_dir / src_util_dir / src_file
  srcs += src_file
endforeach

executable(
  'seewire',
  sources: srcs,
  dependencies: pcap_dep,
  include_directories: incdir,
  install: true,
)
