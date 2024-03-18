'''
QSYM based on AFL
'''
import os
import pathlib
import sys
import time

import peewee
# from .. import config as Config
from autofz import config as Config

from . import afl
from .controller import Controller
# from .db import AFLModel, ControllerModel, QSYMModel, db_proxy
from .db import AFLModel, ControllerModel, EclipserModel, db_proxy
from .fuzzer import FuzzerDriverException, PSFuzzer

CONFIG = Config.CONFIG
FUZZER_CONFIG = CONFIG['fuzzer']


class AFLECLIPSER(afl.AFLBase):
    def gen_run_args(self):
        self.check()
        args = []
        if self.cgroup_path:
            args += ['cgexec', '-g', f'cpu:{self.cgroup_path}']
        args += [self.afl_command, '-i', self.seed, '-o', self.output]
        args += ['-m', 'none']
        args += ['-t', '1000+']
        args += ['-M'] if self.master else ['-S']
        args += [self.name]
        args += ['--', self.target]
        args += self.argument.split(' ')
        return args


class Eclipser(PSFuzzer):
    def __init__(self,
                 seed,
                 output,
                 group,
                 program,
                 argument,
                 afl_name,
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
        self.afl_name = afl_name
        # self.name = 'qsym'
        self.name = 'eclipser'
        self.cgroup_path = cgroup_path
        self.__proc = None

    @property
    def is_ready(self):
        queue_dir = f'{self.output}/{self.name}/queue'
        return os.path.exists(queue_dir)

    @property
    def target(self):
        global FUZZER_CONFIG
        # target_root = FUZZER_CONFIG['qsym']['target_root']
        target_root = FUZZER_CONFIG['eclipser']['target_root']
        return os.path.join(target_root, self.group, self.program,
                            self.program)

    def gen_cwd(self):
        return os.path.dirname(self.target)

    def check(self):
        ret = True
        ret &= os.path.exists(self.target)
        if not ret:
            raise FuzzerDriverException

    def gen_run_args(self):
        self.check()
        global FUZZER_CONFIG
        # qsym_command = FUZZER_CONFIG['qsym']['qsym_command']
        eclipser_command = FUZZER_CONFIG['eclipser']['eclipser_command']
        args = []
        if self.cgroup_path:
            args += ['cgexec', '-g', f'cpu:{self.cgroup_path}']
        args += [eclipser_command]
        args += ['-i', self.seed]
        args += ['-v', str(2)]
        args += ['-s', self.output]
        args += ['-o', self.output + "/eclipser/"]
        args += ['-p', self.target]
        # eclipser_dir = pathlib.Path(self.output + "/eclipser/")
        # eclipser_dir.mkdir(parents=True, exist_ok=True)
        return args


class ECLIPSERController(Controller):
    '''
    1. start one master and one slave
    2. start qsym
    3. need to store pid into database for pause/resume
    '''
    def __init__(self,
                 seed,
                 output,
                 group,
                 program,
                 argument,
                 thread,
                 cgroup_path=''):
        self.db = peewee.SqliteDatabase(
            os.path.join(Config.DATABASE_DIR, 'autofz-eclipser.db'))
        self.name = 'eclipser'
        self.seed = seed
        self.output = output
        self.group = group
        self.program = program
        self.argument = argument
        self.cgroup_path = cgroup_path
        self.afls = []
        self.eclipsers = []
        self.kwargs = {
            'seed': self.seed,
            'output': self.output,
            'group': self.group,
            'program': self.program,
            'argument': self.argument,
            'cgroup_path': self.cgroup_path
        }

    def init(self):
        db_proxy.initialize(self.db)
        self.db.connect()
        self.db.create_tables([AFLModel, EclipserModel, ControllerModel])
        for fuzzer in AFLModel.select():
            afl = AFLECLIPSER(seed=fuzzer.seed,
                          output=fuzzer.output,
                          group=fuzzer.group,
                          program=fuzzer.program,
                          argument=fuzzer.argument,
                          master=fuzzer.master,
                          fuzzer_id=fuzzer.fuzzer_id,
                          cgroup_path=self.cgroup_path,
                          pid=fuzzer.pid)
            self.afls.append(afl)

        for fuzzer in EclipserModel.select():
            eclipser = Eclipser(seed=fuzzer.seed,
                        output=fuzzer.output,
                        group=fuzzer.group,
                        program=fuzzer.program,
                        argument=fuzzer.argument,
                        afl_name=fuzzer.afl_name,
                        cgroup_path=self.cgroup_path,
                        pid=fuzzer.pid)
            self.eclipsers.append(eclipser)

    def get_afl_master(self):
        for AFL in self.afls:
            if AFL.is_master:
                return AFL

    def get_current_active_afl(self):
        '''
        return active AFL instancec
        '''
        active = []
        for afl in self.afls:
            if afl.is_active:
                active.append(afl)
        return active

    def get_current_inactive_afl(self):
        '''
        return inactive AFL instancec
        '''
        inactive = []
        for afl in self.afls:
            if afl.is_inactive:
                inactive.append(afl)
        return inactive

    def start(self):
        if self.afls or self.eclipsers:
            print('already started', file=sys.stderr)
            return
        # start AFL master
        afl_master = AFLECLIPSER(**self.kwargs, master=True, fuzzer_id=1)
        afl_master.start()
        AFLModel.create(**self.kwargs,
                        master=True,
                        pid=afl_master.pid,
                        fuzzer_id=1)
        while not afl_master.is_ready:
            time.sleep(1)
        while not afl_master.fuzzer_stats:
            time.sleep(1)
        # start Eclipser, sync with afl slave like the README
        eclisper = Eclipser(**self.kwargs, afl_name=afl_master.name)
        eclisper.start()
        EclipserModel.create(**self.kwargs, afl_name=afl_master.name, pid=eclisper.pid)
        ControllerModel.create(scale_num=2)
        while not eclisper.is_ready:
            time.sleep(1)
        ready_path = os.path.join(self.output, 'ready')
        pathlib.Path(ready_path).touch(mode=0o666, exist_ok=True)

    def scale(self, scale_num):
        '''
        only increase afl slave
        '''
        if not self.afls and not self.eclipsers:
            print('start first', file=sys.stderr)
            return
        if scale_num == 0:
            self.pause()
            return
        if scale_num < 2:
            # print('scale_num < 2, set to 2')
            scale_num = 2

        num = scale_num - 1  # exclude QSYM SE instance
        current_active = self.get_current_active_afl()
        current_inactive = self.get_current_inactive_afl()
        current_active_num = len(current_active)
        current_inactive_num = len(current_inactive)
        master = self.get_afl_master()
        if current_active_num < num:
            # scale up
            diff = num - current_active_num
            # first resume inative
            resume_num = min(diff, current_inactive_num)
            resumed = 0

            if resume_num and master.is_inactive:
                master.resume()
                resumed += 1

            for afl in current_inactive:
                if resumed == resume_num: break
                if afl.is_active: continue
                afl.resume()
                resumed += 1

            start_id = len(self.afls) + 1
            for i in range(start_id, start_id + diff - resume_num):
                afl = AFLECLIPSER(seed=self.seed,
                              output=self.output,
                              group=self.group,
                              program=self.program,
                              argument=self.argument,
                              cgroup_path=self.cgroup_path,
                              master=False,
                              fuzzer_id=i)
                afl.start()
                AFLModel.create(seed=self.seed,
                                output=self.output,
                                group=self.group,
                                program=self.program,
                                argument=self.argument,
                                cgroup_path=self.cgroup_path,
                                master=False,
                                pid=afl.pid,
                                fuzzer_id=i)
        elif current_active_num > num:
            # scale down
            diff = current_active_num - num
            # pause slave first
            paused = 0
            for afl in current_active:
                if paused == diff: break
                if num >= 1 and afl.is_master:
                    continue
                afl.pause()
                paused += 1
        else:
            # print('does not need to scale', file=sys.stderr)
            return
        controller = ControllerModel.get()
        controller.scale_num = scale_num
        controller.save()

    def pause(self):
        for afl in self.afls:
            afl.pause()
        for eclipser in self.eclipsers:
            eclipser.pause()

    def resume(self):
        '''
        NOTE: prserve scaling
        '''
        controller = ControllerModel.get()
        for afl in self.afls:
            afl.resume()
        for eclipser in self.eclipsers:
            eclipser.resume()
        # let scale to scale down if needed
        self.scale(controller.scale_num)

    def stop(self):
        for afl in self.afls:
            afl.stop()
        for eclipser in self.eclipsers:
            eclipser.stop()
        self.db.drop_tables([AFLModel, EclipserModel, ControllerModel])
