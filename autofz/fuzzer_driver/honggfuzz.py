import os
import pathlib
import sys

import peewee
# from .. import config as Config
from autofz import config as Config

from .controller import Controller
# from .db import ControllerModel, LibFuzzerModel, db_proxy
from .db import ControllerModel, HonggfuzzModel, db_proxy
from .fuzzer import FuzzerDriverException, PSFuzzer

CONFIG = Config.CONFIG
FUZZER_CONFIG = CONFIG['fuzzer']


class Honggfuzz(PSFuzzer):
    def __init__(self,
                 seed,
                 output,
                 group,
                 program,
                 argument,
                 thread=1,
                 cgroup_path='',
                 pid=None):
        '''
        fuzzer_id used to distinguish different slaves
        '''
        super().__init__(pid)
        self.seed = seed
        self.output = output
        self.group = group
        self.program = program
        self.argument = argument
        # self.name = 'libfuzzer'
        self.name = 'honggfuzz'
        self.cgroup_path = cgroup_path
        self.thread = thread
        self.__proc = None
        self.__fuzzer_stats = None

    @property
    def target(self):
        global FUZZER_CONFIG
        # target_root = FUZZER_CONFIG['libfuzzer']['target_root']
        target_root = FUZZER_CONFIG['honggfuzz']['target_root']
        return os.path.join(target_root, self.group, self.program,
                            self.program)

    def gen_cwd(self):
        return os.path.dirname(self.target)

    def pre_run(self):
        crash_dir = os.path.join(self.output, 'crashes')
        queue_dir = os.path.join(self.output, 'queue')
        sync_dir = os.path.join(self.output, 'autofz')
        os.makedirs(crash_dir, exist_ok=True)
        os.makedirs(queue_dir, exist_ok=True)
        os.makedirs(sync_dir, exist_ok=True)
    #检查可执行文件是否存在
    def check(self):
        ret = True
        ret &= os.path.exists(self.target)
        if not ret:
            raise FuzzerDriverException
    #生成指令
    def gen_run_args(self):
        self.check()
        crash_dir = os.path.join(self.output, 'crashes')
        queue_dir = os.path.join(self.output, 'queue')
        sync_dir = os.path.join(self.output, 'autofz')
        command = FUZZER_CONFIG['honggfuzz']['command']
        args = []
        if self.cgroup_path:
            args += ['cgexec', '-g', f'cpu:{self.cgroup_path}']
        args += [command]
        args += ['-n', str(self.thread)]
        args += ['-z']
        args += ['-i', self.seed]
        args += ['-W', crash_dir]
        args += ['-o', queue_dir]
        args += ['--', self.target]
        
        # args += [sync_dir]
        print(args)
        return args


class HONGGFUZZController(Controller):
    def __init__(self,
                 seed,
                 output,
                 group,
                 program,
                 argument,
                 thread=1,
                 cgroup_path=''):
        self.db = peewee.SqliteDatabase(
            # os.path.join(Config.DATABASE_DIR, 'autofz-libfuzzer.db')
            os.path.join(Config.DATABASE_DIR, 'autofz-honggfuzz.db')
            )
        # self.name = 'libfuzzer'
        self.name = 'honggfuzz'
        self.seed = seed
        self.output = output
        self.group = group
        self.program = program
        self.argument = argument
        self.thread = thread
        self.cgroup_path = cgroup_path
        # self.libfuzzers = []
        self.honggfuzzs = []
        self.kwargs = {
            'seed': self.seed,
            'output': self.output,
            'group': self.group,
            'program': self.program,
            'argument': self.argument,
            'thread': self.thread,
            'cgroup_path': self.cgroup_path
        }

    def init(self):
        db_proxy.initialize(self.db)
        self.db.connect()
        # self.db.create_tables([LibFuzzerModel, ControllerModel])
        self.db.create_tables([HonggfuzzModel, ControllerModel])

        # for fuzzer in LibFuzzerModel.select():
        for fuzzer in HonggfuzzModel.select():
            # libfuzzer = LibFuzzer(seed=fuzzer.seed,
            honggfuzz = Honggfuzz(seed=fuzzer.seed,
                                  output=fuzzer.output,
                                  group=fuzzer.group,
                                  program=fuzzer.program,
                                  argument=fuzzer.argument,
                                  thread=fuzzer.thread,
                                  cgroup_path=self.cgroup_path,
                                  pid=fuzzer.pid)
            # self.libfuzzers.append(libfuzzer)
            self.honggfuzzs.append(honggfuzz)

    def start(self):
        # if self.libfuzzers:
        if self.honggfuzzs:
            print('already started', file=sys.stderr)
            return
        # libfuzzer = LibFuzzer(**self.kwargs)
        honggfuzz = Honggfuzz(**self.kwargs)
        # libfuzzer.start()
        honggfuzz.start() 
        # LibFuzzerModel.create(**self.kwargs, pid=libfuzzer.pid)
        HonggfuzzModel.create(**self.kwargs, pid=honggfuzz.pid)
        ControllerModel.create(scale_num=1)
        ready_path = os.path.join(self.output, 'ready')
        pathlib.Path(ready_path).touch(mode=0o666, exist_ok=True)

    def scale(self, scale_num):
        '''
        NOTE: honggfuzz uses thread model
        '''
        pass

    def pause(self):
        # for libfuzzer in self.libfuzzers:
        for honggfuzz in self.honggfuzzs:
            honggfuzz.pause()

    def resume(self):
        '''
        NOTE: prserve scaling
        '''
        controller = ControllerModel.get()
        # for libfuzzer in self.libfuzzers:
        #     libfuzzer.resume()
        for honggfuzz in self.honggfuzzs:
            honggfuzz.resume()

    def stop(self):
        # for libfuzzer in self.libfuzzers:
        #     libfuzzer.stop()
        # self.db.drop_tables([LibFuzzerModel, ControllerModel])
        for honggfuzz in self.honggfuzzs:
            honggfuzz.stop()
        self.db.drop_tables([HonggfuzzModel, ControllerModel])
