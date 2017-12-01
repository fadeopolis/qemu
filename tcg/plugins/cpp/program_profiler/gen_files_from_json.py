#!/usr/bin/env python3

import argparse
import json
import logging
import os
import shutil
import signal
import subprocess
import sys

from jinja2 import Environment, FileSystemLoader
from graphviz import Digraph

symbol_file_prefix = 'symbol_'


def current_file_path():
    return os.path.realpath(__file__)


def template_dir():
    return os.path.join(os.path.dirname(current_file_path()), 'templates')


def ext_dir():
    return os.path.join(os.path.dirname(current_file_path()), 'ext')


def flamegraph_script():
    return os.path.join(
        os.path.dirname(current_file_path()), 'tools/flamegraph.pl')


def get_jinja_env(template_dir):
    return Environment(loader=FileSystemLoader(template_dir))


class TimeoutException(Exception):
    pass


def deadline(timeout, *args):
    """is a the decotator name with the timeout parameter in second"""

    def decorate(f):
        """ the decorator creation """

        def handler(signum, frame):
            """ the handler for the timeout """
            raise TimeoutException(
            )  #when the signal have been handle raise the exception

        def new_f(*args):
            """ the initiation of the handler,
            the lauch of the function and the end of it"""
            signal.signal(signal.SIGALRM,
                          handler)  #link the SIGALRM signal to the handler
            signal.alarm(timeout)  #create an alarm of timeout second
            res = f(*args)  #lauch the decorate function with this parameter
            signal.alarm(0)  #reinitiate the alarm
            return res  #return the return value of the fonction

        new_f.__name__ = f.__name__
        return new_f

    return decorate


@deadline(10)
def render_dot_in_limited_time(dot, out_dot_file, out_img_file):
    try:
        dot.render(out_dot_file)
    except TimeoutException:
        logging.warning('DOT_FILE: generate file was too long, skipping it...')
        try:
            os.remove(out_img_file)
        except OSError:
            pass


def log():
    global _logger
    return _logger


def setup_logger():
    global _logger
    _logger = logging.getLogger()
    _logger.setLevel(logging.DEBUG)
    stream_handler = logging.StreamHandler()
    stream_handler.setLevel(logging.DEBUG)
    _logger.addHandler(stream_handler)


def create_output_dir(output_dir):
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)


def load_json(input_json):
    with open(input_json) as f:
        data = json.load(f)

    return data


def get_symbol_src_start(s):
    # first block has the lowest id, which matches the first time block
    # was created, thus the entry block of function
    first_block = s['basic_blocks'][0]
    first_block_instrs = first_block['instructions']
    if not first_block_instrs:
        return ''
    first_instr = first_block_instrs[0]
    src = ''
    src_node = first_instr['src']
    if src_node:
        src = src_node['file'] + ':' + str(src_node['line'])
    return src


def get_symbol_name(s):
    name = s['name']
    if not name:
        name = hex(s['pc'])
    return name


def get_symbol_url(s):
    return symbol_file_prefix + str(s['id']) + '.html'


def generate_index(symbols, call_stacks, original_json_input, output_dir,
                   output_file, j2env, template_file):
    flamegraph_file_name = output_file + '.flamegraph.txt'
    flamegraph_image_file_name = flamegraph_file_name + '.svg'
    flamegraph_file = os.path.join(output_dir, flamegraph_file_name)
    flamegraph_image_file = os.path.join(output_dir,
                                         flamegraph_image_file_name)
    output_dot_file_name = output_file + '.dot.txt'
    output_dot_file = os.path.join(output_dir, output_dot_file_name)
    output_file = os.path.join(output_dir, output_file)

    syms = []
    dot = Digraph(format='svg')

    # create list of symbols and dot graph
    for s in sorted(symbols, key=lambda x: x['pc']):
        id = s['id']
        sym_url = get_symbol_url(s)
        name = get_symbol_name(s)
        pc = hex(s['pc'])
        size = s['size']

        src = get_symbol_src_start(s)

        binary = s['file']
        if not binary:
            binary = ''

        sym = dict(
            name=name, pc=pc, size=size, src=src, binary=binary, url=sym_url)
        syms.append(sym)

        dot_name = name
        if not dot_name:
            dot_name = pc
        dot.node(str(id), label=dot_name, URL=sym_url)
        for succ in s['successors']:
            dot.edge(str(id), str(succ['id']))

    log().info('generate index file %s', output_file)
    out = j2env.get_template(template_file).render(
        title='Index',
        dot_file=output_dot_file_name,
        svg_file=output_dot_file_name + '.svg',
        flamegraph_file=flamegraph_image_file_name,
        json_file=original_json_input,
        symbols=syms)
    with open(output_file, 'w') as f:
        f.write(out)

    log().info('generate flamegraph file %s', flamegraph_file)
    with open(flamegraph_file, 'w') as f:
        for cs in call_stacks:
            f.write('all')
            for s in cs['symbols']:
                f.write(';' + s['name'])
            f.write(' ' + str(cs['count']) + '\n')
    with open(flamegraph_file, 'r') as infile:
        with open(flamegraph_image_file, 'w') as outfile:
            subprocess.check_call(
                flamegraph_script(), stdin=infile, stdout=outfile)

    svg_out = output_dot_file + '.svg'
    log().info('generate dot file %s', output_dot_file)
    log().info('generate svg file %s', svg_out)
    render_dot_in_limited_time(dot, output_dot_file, svg_out)


@deadline(10)
def generate_symbol_file(sym, output_dir, output_file, index_file, j2env,
                         template_file, sym_number, sym_total_number):
    output_dot_file_name = output_file + '.dot.txt'
    output_dot_file = os.path.join(output_dir, output_dot_file_name)
    output_file = os.path.join(output_dir, output_file)

    dot = Digraph(format='svg')
    dot.attr('node', shape='box')

    sources = []
    assembly = []

    for s in sym['src']:
        src = dict(
            file=s['file'],
            line=s['line'],
            src=s['str'],
            executed=s['executed'])
        sources.append(src)

    for i in sym['instructions']:
        inst = dict(pc=hex(i['pc']), asm=i['str'], executed=i['executed'])
        assembly.append(inst)

    for b in sym['basic_blocks']:
        id = b['id']
        pc = b['pc']
        b_label = hex(pc)
        b_label += '\n_______________________'
        for src in b['src']:
            b_label += '\n'
            b_label += src['str']
        b_label += '\n_______________________'
        for i in b['instructions']:
            b_label += '\n'
            b_label += i['str']

        loop_header = b['loop_header']
        if loop_header:
            b_label += '\n_______________________'
            b_label += '\n'
            b_label += 'LOOP ' + hex(loop_header['pc'])

        called_symbols = dict()

        for succ in b['successors']:
            is_in_same_symbol = False
            for b in sym['basic_blocks']:
                if b['id'] == succ['id']:
                    is_in_same_symbol = True

            if is_in_same_symbol:
                dot.edge(str(id), str(succ['id']))
            else:
                for s in succ['symbols']:
                    called_symbols[s['id']] = s

        if len(called_symbols.values()) > 0:
            b_label += '\n_______________________'

        for s in called_symbols.values():
            called_symbol_name = s['name']
            if not called_symbol_name:
                called_symbol_name = hex(pc)
            b_label += '\nCALL ' + called_symbol_name

        if len(b['symbols']) > 1:
            b_label += '\n_______________________'
            for s in b['symbols']:
                name = get_symbol_name(s)
                b_label += '\nSHARED BLOCK ' + name

        dot.node(str(id), label=b_label)

    name = get_symbol_name(sym)
    pc = hex(sym['pc'])
    orig_file = sym['file']
    src = get_symbol_src_start(sym)
    size = sym['size']

    def list_builder(syms):
        res = []
        for s in syms:
            data = dict()
            data['name'] = get_symbol_name(s)
            data['url'] = get_symbol_url(s)
            res.append(data)
        return res

    successors = list_builder(sym['successors'])
    predecessors = list_builder(sym['predecessors'])

    progress_str = '[' + str(sym_number) + '/' + str(sym_total_number) + ']'
    log().info('%s generate symbol file %s', progress_str, output_file)
    out = j2env.get_template(template_file).render(
        title='Symbol',
        dot_file=output_dot_file_name,
        svg_file=output_dot_file_name + '.svg',
        index_file=index_file,
        sym_name=name,
        sym_pc=pc,
        sym_size=size,
        sym_file=orig_file,
        sym_src=src,
        sym_successors=successors,
        sym_predecessors=predecessors,
        sources=sources,
        assembly=assembly)
    with open(output_file, 'w') as f:
        f.write(out)

    svg_out = output_dot_file + '.svg'
    log().info('%s generate dot file %s', progress_str, output_dot_file)
    log().info('%s generate svg file %s', progress_str, svg_out)
    dot.render(output_dot_file)


def generate_files(input_json, output_dir):
    log().info('generate files in %s', output_dir)
    create_output_dir(output_dir)
    j = load_json(input_json)

    log().info('read templates from %s', template_dir())
    j2env = get_jinja_env(template_dir())

    out_ext_dir = os.path.join(output_dir, 'ext')
    if os.path.exists(out_ext_dir):
        shutil.rmtree(out_ext_dir)
    shutil.copytree(ext_dir(), out_ext_dir)
    shutil.copyfile(input_json, os.path.join(output_dir, 'data.json'))
    output_index = 'index.html'

    # replace symbols/blocks id by objects
    # create dict for symbols/blocks
    symbols_dict = dict()
    for s in j['symbols']:
        symbols_dict[s['id']] = s
    blocks_dict = dict()
    for b in j['basic_blocks']:
        blocks_dict[b['id']] = b
    # map id to objects
    for s in j['symbols']:
        if not s['name']:
            s['name'] = hex(s['pc'])
        s['successors'] = [
            symbols_dict[succ_id] for succ_id in s['successors']
        ]
        s['basic_blocks'] = [
            blocks_dict[block_id] for block_id in s['basic_blocks']
        ]
    for b in j['basic_blocks']:
        b['successors'] = [blocks_dict[succ_id] for succ_id in b['successors']]
        if b['loop_header']:
            b['loop_header'] = blocks_dict[b['loop_header']]
        b['symbols'] = [symbols_dict[sym_id] for sym_id in b['symbols']]
    for cs in j['call_stacks']:
        cs['symbols'] = [symbols_dict[sym_id] for sym_id in cs['symbols']]

    # compute predecessors
    for s in j['symbols']:
        s.update({'predecessors': []})

    for s in j['symbols']:
        for succ in s['successors']:
            succ['predecessors'].append(s)

    generate_index(j['symbols'], j['call_stacks'], 'data.json', output_dir,
                   output_index, j2env, 'index.html')

    total_syms = len(j['symbols'])
    sym_number = 1
    for s in j['symbols']:
        output_file = symbol_file_prefix + str(s['id']) + '.html'
        try:
            generate_symbol_file(s, output_dir, output_file, output_index,
                                 j2env, 'symbol.html', sym_number, total_syms)
        except TimeoutException:
            logging.warning(
                'SYMBOL_FILE: generate file was too long, skipping it...')
            try:
                os.remove(os.path.join(output_dir, output_file))
            except OSError:
                pass

        sym_number += 1


def main(argv):
    setup_logger()

    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-o', '--output-dir', help='output directory', required=True)
    parser.add_argument('-i', '--input-file', help='input file', required=True)
    args = parser.parse_args(argv)
    generate_files(args.input_file, args.output_dir)


if __name__ == '__main__':
    main(sys.argv[1:])
