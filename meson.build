project(
  'qobuzconnect2mpd',
  'cpp',
  license: 'LGPL 2.1+',
  version: '1.0.0',
  default_options: ['cpp_std=c++17', 'buildtype=debugoptimized'],
  meson_version: '>=0.49',
)

# MDU_INCLUDE_LOG (log.h include path in medocutils shared code): initially thought not needed
# but actually now needed because libupnpp.pc was changed to not set -I${includedir}/libupnpp
# in order to make sure of avoiding possible collisions by forcing user code to always use
#  #include <libupnpp/xxx.h>

######## upmpdcli itself
#if get_option('upmpdcli')
#  deps = []
#  dep_libupnpp = dependency('libupnpp')
#  deps += dep_libupnpp
#  deps += dependency('libcurl')
#  deps += dependency('libmicrohttpd')
#  deps += dependency('jsoncpp')
#  deps += dependency('libmpdclient')
#  deps += dependency('threads')
  
#  upmpdcli_incdir = include_directories('src')
  
#  upmpdcli_sources = files(
#    'src/avtransport.cxx',
#    'src/chrono.cpp',
#    'src/closefrom.cpp',
#    'src/conftree.cpp',
#    'src/conman.cxx',
#    'src/execmd.cpp',
#    'src/main.cxx',
#    'src/mediaserver/cdplugins/cmdtalk.cpp',
#    'src/mediaserver/cdplugins/curlfetch.cpp',
#    'src/mediaserver/cdplugins/netfetch.cpp',
#    'src/mediaserver/cdplugins/plgwithslave.cxx',
#    'src/mediaserver/cdplugins/streamproxy.cpp',
#    'src/mediaserver/contentdirectory.cxx',
#    'src/mediaserver/mediaserver.cxx',
#    'src/mpdcli.cxx',
#    'src/netcon.cpp',
#    'src/ohcredentials.cxx',
#    'src/ohinfo.cxx',
#    'src/ohmetacache.cxx',
#    'src/ohplaylist.cxx',
#    'src/ohproduct.cxx',
#    'src/ohradio.cxx',
#    'src/ohreceiver.cxx',
#    'src/ohservice.cxx',
#    'src/ohsndrcv.cxx',
#    'src/ohtime.cxx',
#    'src/ohvolume.cxx',
#    'src/pathut.cpp',
#    'src/protocolinfo.cxx',
#    'src/readfile.cpp',
#    'src/renderctl.cxx',
#    'src/smallut.cpp',
#    'src/sysvshm.cpp',
#    'src/upmpd.cxx',
#    'src/upmpdutils.cxx',
#    'src/urlmorph.cxx',
#  )
  
#  auto = configuration_data()
#  auto.set_quoted('UPMPDCLI_VERSION', meson.project_version())
#  configure_file(
#    input: 'src/config.h.in',
#    output: 'config.h',
#    configuration: auto,
#  )
  
#  upmpdcli_datadir = get_option('prefix') / get_option('datadir') / 'upmpdcli'
  
#  executable(
#    'upmpdcli',
#    upmpdcli_sources,
#    include_directories: upmpdcli_incdir,
#    dependencies: deps,
#    install: true,
#    cpp_args: ['-DDATADIR="' + upmpdcli_datadir + '"', '-DMDU_INCLUDE_LOG="libupnpp/log.h"'],
#  )
#endif
##### End upmpdcli

########################### qconnect2mpd (Qobuz Connect receiver daemon)

qc_deps = []
qc_deps += dependency('libcurl')
qc_deps += dependency('libmicrohttpd')
qc_deps += dependency('jsoncpp')
qc_deps += dependency('libmpdclient')
qc_deps += dependency('openssl')
qc_deps += dependency('threads')

qc_sources = files(
  'src/conftree.cpp',
  'src/smallut.cpp',
  'src/pathut.cpp',
  'src/qconnect/main.cxx',
  'src/qconnect/mdns.cxx',
  'src/qconnect/httphandler.cxx',
  'src/qconnect/wsession.cxx',
  'src/qconnect/qobuzapi.cxx',
  'src/qconnect/segstream.cxx',
  'src/qconnect/mpdctl.cxx',
  'src/qconnect/qcmgr.cxx',
  'src/qconnect/proto.cxx',
)

executable(
  'qobuzconnect2mpd',
  qc_sources,
  include_directories: include_directories('src', 'src/qconnect'),
  dependencies: qc_deps,
  install: true,
  cpp_args: [],
)

qc_proto_test = executable(
  'qconnect-proto-test',
  files('tests/qconnect_proto_test.cxx', 'src/qconnect/proto.cxx'),
  include_directories: include_directories('src/qconnect'),
  dependencies: dependency('threads'),
)
test('qconnect-proto', qc_proto_test)

qc_log_test = executable(
  'qconnect-log-test',
  files('tests/qclog_test.cxx'),
  include_directories: include_directories('src/qconnect'),
  dependencies: dependency('threads'),
)
test('qconnect-log', qc_log_test)

qc_segstream_test = executable(
  'qconnect-segstream-test',
  files('tests/segstream_test.cxx', 'src/qconnect/segstream.cxx'),
  include_directories: include_directories('src/qconnect'),
  dependencies: [dependency('libcurl'), dependency('openssl'), dependency('threads')],
)
test('qconnect-segstream', qc_segstream_test)

qc_http_stream_test = executable(
  'qconnect-http-stream-test',
  files(
    'tests/httphandler_stream_test.cxx',
    'src/qconnect/httphandler.cxx',
    'src/qconnect/segstream.cxx',
  ),
  include_directories: include_directories('src/qconnect'),
  dependencies: [
    dependency('libcurl'),
    dependency('libmicrohttpd'),
    dependency('jsoncpp'),
    dependency('openssl'),
    dependency('threads'),
  ],
)
test('qconnect-http-stream', qc_http_stream_test)

qc_qobuz_token_test = executable(
  'qconnect-qobuz-token-test',
  files(
    'tests/qobuzapi_token_test.cxx',
    'src/qconnect/qobuzapi.cxx',
    'src/qconnect/segstream.cxx',
  ),
  include_directories: include_directories('src/qconnect'),
  dependencies: [
    dependency('libcurl'),
    dependency('jsoncpp'),
    dependency('openssl'),
    dependency('threads'),
  ],
)
test('qconnect-qobuz-token', qc_qobuz_token_test)
#### End qconnect2mpd

########################### Optional Configuration GUI
#if get_option('confgui')

#  qt5_mod = import('qt5')
#  qt5widgets = dependency('qt5', modules: 'Widgets')

#  processed = qt5_mod.preprocess(
#    moc_headers: ['cfgui/mainwindow.h', 'cfgui/confgui.h'],
#  )

#  upmpdcli_config_sources = files(
#    'cfgui/confgui.cpp',
#    'cfgui/xmltoconfgui.cpp',
#    'cfgui/confmain.cpp',
#    'cfgui/loclog/log.cpp',
#    'src/conftree.cpp',
#    'src/pathut.cpp',
#    'src/smallut.cpp',
#  )
#  upmpdcli_config_sources += processed

#  deps = [qt5widgets,]
#  cppargs = []
#  idir = 'src'
#  if get_option('confgui_listifs')
#    deps += dep_libupnpp
#    cppargs += '-DENABLE_NETIF=1 -DMDU_INCLUDE_LOG="loclog/log.h"'
#    idir = dep_libupnpp.get_pkgconfig_variable('includedir') / 'libupnpp'
#  endif
#  cfgincludes = include_directories(
#    'src',
#    'cfgui',
#    'cfgui/loclog',
#     idir,
#  )

#  executable(
#    'upmpdcli-config',
#    sources: upmpdcli_config_sources,
#    install: true,
#    dependencies: deps,
#    include_directories: cfgincludes,
#    cpp_args: cppargs,
#  )

#endif

############################ Optional scctl songcast control and web interface

#if get_option('scctl')
#  scctl_sources = files(
#    'scctl_src/scctl.cpp',
#    'src/netcon.cpp',
#    'src/smallut.cpp',
#    'src/upmpdutils.cxx',
#  )

#  scctl_includes = include_directories(
#    dep_libupnpp.get_pkgconfig_variable('includedir') / 'libupnpp',
#    'src',
#    'scctl_src',
#  )
#  executable(
#    'scctl',
#    sources: scctl_sources,
#    install: true,
#    dependencies: [dep_libupnpp],
#    include_directories: scctl_includes,
#  )

#  install_subdir(
#    'web',
#    install_dir: get_option('datadir') / 'upmpdcli',
#    exclude_directories: '__pycache__',
#  )
#endif

########################## Install data

qobuzconnect2mpd_bin = join_paths(
  get_option('prefix'),
  get_option('bindir'),
  'qobuzconnect2mpd',
)

init_system = get_option('init_system')
if init_system == 'auto'
  host_system = host_machine.system()
  if host_system == 'freebsd'
    init_system = 'freebsd'
  elif host_system == 'linux'
    init_system = 'systemd'
  else
    init_system = 'none'
  endif
endif

systemd_conf = configuration_data()
systemd_conf.set('QOBUZCONNECT2MPD_BIN', qobuzconnect2mpd_bin)

if init_system == 'systemd'
  systemd_unit = configure_file(
    input: 'systemd/qobuzconnect2mpd.service.in',
    output: 'qobuzconnect2mpd.service',
    configuration: systemd_conf,
  )

  install_data(systemd_unit, install_dir: get_option('datadir') / 'systemd/user')
elif init_system == 'freebsd'
  qobuzconnect2mpd_config = join_paths(
    get_option('prefix'),
    get_option('sysconfdir'),
    'qobuzconnect2mpd.conf',
  )

  freebsd_conf = configuration_data()
  freebsd_conf.set('PREFIX', get_option('prefix'))
  freebsd_conf.set('BINDIR', join_paths(get_option('prefix'), get_option('bindir')))
  freebsd_conf.set('QOBUZCONNECT2MPD_CONFIG', qobuzconnect2mpd_config)

  freebsd_rc = configure_file(
    input: 'freebsd/qobuzconnect2mpd.in',
    output: 'qobuzconnect2mpd.rc',
    configuration: freebsd_conf,
  )

  install_data(
    freebsd_rc,
    install_dir: get_option('sysconfdir') / 'rc.d',
    rename: 'qobuzconnect2mpd',
    install_mode: 'rwxr-xr-x',
  )

  install_data(
    'conf/qobuzconnect2mpd.conf.example',
    install_dir: get_option('sysconfdir'),
    rename: 'qobuzconnect2mpd.conf.sample',
  )

  meson.add_install_script(
    'freebsd/install-service-account.sh',
    'qobuzconnect2mpd',
    '/var/db/qobuzconnect2mpd',
  )
endif

#upmpdcli_data = files(
#  'src/AVTransport.xml',
#  'src/ConnectionManager.xml',
#  'src/OHCredentials.xml',
#  'src/OHInfo.xml',
#  'src/OHPlaylist.xml',
#  'src/OHProduct.xml',
#  'src/OHRadio.xml',
#  'src/OHReceiver.xml',
#  'src/OHTime.xml',
#  'src/OHVolume.xml',
#  'src/RenderingControl.xml',
#  'src/description.xml',
#  'src/icon.png',
#  'src/mediaserver/ContentDirectory.xml',
#  'src/mediaserver/MS-description.xml',
#  'src/presentation.html',
#  'src/protocolinfo.txt',
#  'src/upmpdcli.conf-dist',
#  'src/upmpdcli.conf-xml',
#)
#install_data(upmpdcli_data, install_dir: get_option('datadir') / 'upmpdcli')

#install_data('src/upmpdcli.conf-dist', install_dir: '/etc')

#install_subdir(
#  'rdpl2stream',
#  install_dir: get_option('datadir') / 'upmpdcli',
#  exclude_directories: '__pycache__',
#  exclude_files: [
#    'tststreams.txt',
#  ],
#)

#install_subdir(
#  'samplescripts',
#  install_dir: get_option('datadir') / 'upmpdcli' / 'src_scripts',
#  strip_directory: true,
#)

#install_subdir(
#  'src/radio_scripts',
#  install_dir: get_option('datadir') / 'upmpdcli',
#  exclude_directories: 'npr',
#)

#install_subdir(
#  'src/mediaserver/cdplugins',
#  install_dir: get_option('datadir') / 'upmpdcli',
#  exclude_directories: [
#    'attic',
#    '.deps',
#    'uprcl/testrunuprcl.sh',
#    'bbc/__pycache__',
#    'hra/__pycache__',
#    'mother-earth-radio/__pycache__',
#    'pycommon/__pycache__',
#    'qobuz/__pycache__',
#    'qobuz/api/__pycache__',
#    'radio-browser/__pycache__',
#    'radio-paradise/__pycache__',
#    'subsonic/__pycache__',
#    'tidal/__pycache__',
#    'upradios/__pycache__',
#    'uprcl/__pycache__',
#  ],
#  exclude_files: [
#    'abuffer.h',
#    'bufxchange.h',
#    'cdplugin.hxx',
#    'cmdtalk.cpp',
#    'cmdtalk.h',
#    'curlfetch.cpp',
#    'curlfetch.h',
#    'netfetch.cpp',
#    'netfetch.h',
#    'plgwithslave.cxx',
#    'plgwithslave.hxx',
#    'streamproxy.cpp',
#    'streamproxy.h',
#    'uprcl/testrunuprcl.sh',
#  ],
#)

#meson.add_install_script('tools/installconfig.sh')

#install_man('man/upmpdcli.1')
#install_man('man/upmpdcli.conf.5')
