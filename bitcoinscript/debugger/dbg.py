"""
Implementation of the debugger.
"""

from ..format import iter_script_parts_as_strings
from .execution import get_inout_script_execution_steps

###############################################################################
# curses setup
import os
os.environ.setdefault('TERM', 'xterm-256color')
import curses
###############################################################################

###############################################################################
# settings

TAPE_SPACE_SIZE = 4
TAPE_BORDER = '='
TAPE_INCLUDE_OP_PREFIX = True
TAPE_OP_CARET = '>'
TAPE_ACTIVE_OP_COLOR = 7
TAPE_END_MARKER = '###'

STACK_MAX_SIZE = 20
STACK_WIDTH = 18
EMPTY_VALUE_STRING = '<<empty value>>'
STACK_ACTIVE_COLOR = 0
STACK_INACTIVE_COLOR = 9
STACK_CHANGE_COLOR = 12

SUCCESS_COLOR = 3
ERROR_COLOR = 2
    
###############################################################################

class Tape:
    """
    A tape-state, which can draw itself in a window.
    """
    
    def __init__(self, script, last_op = None, label = None, counter = None):
        self.script = script
        self.last_op = last_op
        self.label = label
        self.counter = counter

    @property
    def script_len(self):
        return len(list(self.script))

    @property
    def is_at_beginning(self):
        last_op_idx = -1 if self.last_op is None else self.last_op[3]
        return last_op_idx < 0
        
    @property
    def is_at_end(self):
        last_op_idx = -1 if self.last_op is None else self.last_op[3]
        return last_op_idx >= self.script_len - 1
        
    def draw(self, window):
        mid_line = 1
        height, width = window.getmaxyx()
        
        script_tokens = [[], [], []] # head, mid, tail
        last_op_idx = -1 if self.last_op is None else self.last_op[3]
        next_op_idx = last_op_idx + 1
        tokens = list(iter_script_parts_as_strings(self.script)) + [ TAPE_END_MARKER ]
        script_tokens = [
            tokens[:next_op_idx],
            [ tokens[next_op_idx] ] if next_op_idx < len(tokens) else [],
            tokens[next_op_idx+1:],
        ]
        if not TAPE_INCLUDE_OP_PREFIX:
            def drop_op(x):
                if x.startswith('OP_'):
                    return x[len('OP_'):]
                return x
            script_tokens = [
                [ drop_op(x) for x in l ]
                for l in script_tokens
            ]

        space = TAPE_SPACE_SIZE * ' '
        head_str = space.join(script_tokens[0]) + space
        mid_str = TAPE_OP_CARET + space.join(script_tokens[1])
        tail_str = space + space.join(script_tokens[2])
        
        pivot_pos = int(width * 0.4)
        head_start_pos = pivot_pos - len(head_str)
        if head_start_pos < 0:
            # trim beginning
            head_str = head_str[-head_start_pos:]
            if len(head_str) > 2:
                head_str = '/' + head_str[2:]
            head_start_pos = 0
        head_str = (' ' * (pivot_pos - len(head_str))) + head_str
        assert len(head_str) == pivot_pos, (len(head_str), pivot_pos)
        
        window.move(mid_line, 0)
        window.clrtoeol()
        _addstr(window, head_str)
        _addstr(window, mid_str, curses.color_pair(TAPE_ACTIVE_OP_COLOR))
        _addstr(window, tail_str)
        
        for offset in (-1, 1):
            window.move(mid_line-offset, 0)
            _addstr(window, mid_line-offset, 0, TAPE_BORDER * (width-1))
        if self.label is not None:
            _addstr(window, mid_line-1, 4, ' %s ' % self.label)
        if self.counter is not None:
            counter_str = ' %s/%s ' % self.counter
            _addstr(window, mid_line-1, width - len(counter_str) - 2, counter_str)

class Stack:
    """
    A stack-state, which can draw itself in a window.
    """
    
    def __init__(self, stack, prev_stack = None, label = 'STACK', color = 0):
        self.stack = stack
        self.prev_stack = getattr(prev_stack, 'stack', prev_stack)
        self.label = label
        self.color = color
        
    def draw(self, window):
        height, width = window.getmaxyx()
        bottom_line = height - 1
        mid_col = width // 2

        _addstr_centered(window, bottom_line, mid_col, self.label, self.color)
        stack = self.stack
        is_trimmed = False
        if len(stack) > STACK_MAX_SIZE:
            stack = stack[len(stack)-STACK_MAX_SIZE:]
            is_trimmed = True
        diff_idx = self._find_diff_idx()
        for i, v in enumerate(stack):
            if is_trimmed and i == 0:
                y = '...'
            else:
                y = self.format_value(v.hex(), STACK_WIDTH)
            color = self.color if i < diff_idx else curses.color_pair(STACK_CHANGE_COLOR)
            _addstr_centered(window, bottom_line - i - 1, mid_col, y, color)

    def format_value(self, value, max_value_len):
        if len(value) > max_value_len:
            part_len = (max_value_len - 3) // 2
            assert part_len > 0, part_len
            value = '%s...%s' % (value[:part_len], value[-part_len:])
        if len(value) == 0:
            value = EMPTY_VALUE_STRING
        return value
    
    def _find_diff_idx(self):
        if self.prev_stack is None:
            return 99999999
        i = 0
        for v1, v2 in zip(self.stack, self.prev_stack):
            if v1 != v2:
                break
            i += 1
        return i

class DebuggerState:
    """
    A state in a debugging session, holding all ScriptExecutionStates, and the index of the current state.
    This class is also responsible for visually displaying the state in a window.
    """
    
    def __init__(self, window, states, initial_state_idx = 0):
        self.states = states
        self.cur_state_idx = initial_state_idx
        
        # create sub-windows:
        self.window = window
        height, width = window.getmaxyx()
        mid_col = width // 2        
        self.tape_win = curses.newwin(3, width, height - 5, 0)
        self.message_win = curses.newwin(1, width, height - 2, 0)
        self.stack_win = curses.newwin(height - 8, STACK_WIDTH, 1, mid_col - STACK_WIDTH//2)
        self.prev_stack_win = curses.newwin(height - 8, STACK_WIDTH, 1, (mid_col - STACK_WIDTH)//2)
        self.next_stack_win = curses.newwin(height - 8, STACK_WIDTH, 1, (3*mid_col - STACK_WIDTH)//2)
    
    @property
    def is_at_beginning(self):
        return self.cur_state_idx == 0
    
    @property
    def is_at_end(self):
        return self.cur_state_idx >= len(self.states) - 1
    
    @property
    def cur_state(self):
        return self.states[self.cur_state_idx]

    def get_state(self, offset):
        i = self.cur_state_idx + offset
        if 0 <= i < self.num_states:
            return self.states[i]
        
    @property
    def num_states(self):
        return len(self.states)
    
    # Tape, Stack, etc.
    
    def get_tape_from_state(self, state):
        return Tape(
            state.scriptIn, state.last_op,
            label = state.scriptRole,
            counter = (self.cur_state_idx, self.num_states-1),
        )

    def get_stack_from_state(self, state, prev_stack, is_active = True, label = None):
        color = STACK_ACTIVE_COLOR if is_active else STACK_INACTIVE_COLOR
        return Stack(state.stack, prev_stack, label, curses.color_pair(color))
    
    def get_message_from_state(self, state):
        if state.is_error:
            return self.format_error(state), ERROR_COLOR
        if state.is_final:
            return 'SUCCESS', SUCCESS_COLOR
        
    def format_error(self, state):
        return '*ERROR* %s' % state.error_string
    
    # Transitions
    
    def switch_state(self, idx):
        self.cur_state_idx = idx
    
    def next_state(self):
        i = self.cur_state_idx + 1
        if i < self.num_states:
            self.switch_state(i)
        
    def prev_state(self):
        i = self.cur_state_idx - 1
        if i >= 0:
            self.switch_state(i)
            
    def first_state(self):
        self.switch_state(0)
        
    def last_state(self):
        self.switch_state(self.num_states - 1)
    
    # Drawing

    def draw(self):
        
        height, width = self.window.getmaxyx()
        
        state = self.cur_state
        if state.is_error:
            msg_state = state
            cur_state = self.get_state(-1)
            prev_state = self.get_state(-2)
            next_state = None
        elif state.is_final:
            msg_state = state
            cur_state = self.get_state(-1)
            prev_state = self.get_state(-2)
            next_state = None
        else:
            msg_state = state
            cur_state = state
            prev_state = self.get_state(-1)
            next_state = self.get_state(+1)
        del state

        tape = self.get_tape_from_state(cur_state)
        
        if tape is not None:
            if tape.is_at_end:
                next_state = None
            if tape.is_at_beginning:
                prev_state = None
        
        if next_state is not None and next_state.is_error:
            next_state = None
        
        self.tape_win.clear()
        if tape is not None:
            tape.draw(self.tape_win)
        self.tape_win.refresh()

        self.prev_stack_win.clear()
        prev_stack = None
        if prev_state is not None:
            stack = self.get_stack_from_state(prev_state, None, is_active = False, label = 'PREV STACK')
            if stack is not None:
                stack.draw(self.prev_stack_win)
            prev_stack = stack
        self.prev_stack_win.refresh()
        
        self.next_stack_win.clear()
        if next_state is not None:
            stack = self.get_stack_from_state(next_state, None, is_active = False, label = 'NEXT STACK')
            if stack is not None:
                stack.draw(self.next_stack_win)
        self.next_stack_win.refresh()
        
        self.stack_win.clear()
        stack = self.get_stack_from_state(cur_state, prev_stack, is_active = True, label = 'STACK')
        if stack is not None:
            stack.draw(self.stack_win)
        self.stack_win.refresh()

        msg_info = self.get_message_from_state(msg_state)
        self.message_win.clear()
        if msg_info is not None:
            msg, msg_color = msg_info
            _addstr(self.message_win, msg, curses.color_pair(msg_color))
        self.message_win.refresh()
        
        _addstr_centered(self.window, height - 1, width//2, '[Press H for Help]')


class SimpleReadKeyApp:

    def __init__(self, window):
        self.window = window
    
    def run(self):
        self._init_window()
        self.refresh()
        try:
            self._run_mainloop()
        except KeyboardInterrupt:
            pass
        
    def _run_mainloop(self):
        commands = self.get_commands()
        while True:
            c = self.window.getch()
            refresh = False
            for cmd_keys, cmd_func in commands:
                if c in cmd_keys:
                    refresh = cmd_func()
                    break
            if refresh:
                self.refresh()
        
    def _init_window(self):
        curses.curs_set(0)
        curses.start_color()
        curses.use_default_colors()
        for i in range(0, curses.COLORS):
            curses.init_pair(i + 1, i, -1)
        self.window.clear()
    
    def refresh(self):
        self.window.refresh()
    
    def get_commands(self):
        return [
            ([ord('q'), ord('Q')], self.quit),
        ]

    def quit(self):
        """ Quit the debugger """
        self.window.clear()
        self.window.refresh()
        raise KeyboardInterrupt
    

class HelpScreen(SimpleReadKeyApp):
    
    def __init__(self, window, app):
        super().__init__(window)
        self.app = app
    
    def refresh(self):
        commands = self.app.get_commands()
        height, width = self.window.getmaxyx()
        _addstr_centered(self.window, 0, width//2, 'HELP SCREEN')
        _addstr_centered(self.window, height-1, width//2, '[Press Q to go back]')
        
        _addstr_centered(self.window, 3, width//2, 'Keyboard Shortcuts')
        for i, (cmd_keys, cmd_func) in enumerate(commands):
            s = ' / '.join( curses.keyname(k).decode() for k in cmd_keys )
            _addstr(self.window, i+5, 2, s)
            _addstr(self.window, i+5, 30, cmd_func.__doc__.strip())
        super().refresh()

class SimpleReadKeyAppWithHelp(SimpleReadKeyApp):

    def help_screen(self):
        """ Display a HELP screen """
        HelpScreen(self.window, self).run()
        return True

    def get_commands(self):
        return [ ([ord('h'), ord('H')], self.help_screen) ] + \
            super().get_commands()

class DebuggerApp(SimpleReadKeyAppWithHelp):
    """
    A debugging session, responsible for setting up the GUI, running the main loop, etc.
    """

    def __init__(self, window, states):
        super().__init__(window)
        self.states_manager = DebuggerState(window, states)
        
    def get_commands(self):
        return super().get_commands() + [
            ([ord('n'), curses.KEY_RIGHT], self.next_state),
            ([ord('b'), curses.KEY_LEFT], self.prev_state),
            ([curses.KEY_HOME], self.first_state),
            ([curses.KEY_END], self.last_state),
        ]

    def refresh(self):
        super().refresh()
        self.states_manager.draw()

    def next_state(self):
        """ NEXT step """
        self.states_manager.next_state()
        return True
    
    def prev_state(self):
        """ PREV step """
        self.states_manager.prev_state()
        return True
    
    def first_state(self):
        """ Go to FIRST step """
        self.states_manager.first_state()
        return True
    
    def last_state(self):
        """ Go to LAST step """
        self.states_manager.last_state()
        return True
    

###############################################################################
# Utility functions

def run_in_debugger(*args, **kwargs):
    """
    Run the script, and start a new debugger session.
    Arguments are passed to get_inout_script_execution_steps() as is.
    """
    states = get_inout_script_execution_steps(*args, **kwargs)
    return start_debugger(states)

def start_debugger(states):
    """
    Start a debugger session, with given execution steps.
    """
    return curses.wrapper(lambda stdscr: _start_debugger(stdscr, states))

def _start_debugger(stdscr, states):
    d = DebuggerApp(stdscr, states)
    d.run()

################################################################################
# GUI helpers

def _addstr(window, *a):
    if isinstance(a[0], int):
        # row and col are given
        row, col, s, *args = a
    else:
        # using cur row/col
        row, col = window.getyx()
        s, *args = a
    height, width = window.getmaxyx()
    # overflow to the left
    if col < 0:
        s = s[-col:]
        col = 0
    # overflow to the right
    over = col + len(s) + 1 - width
    if over > 0:
        s = s[: -over]
    window.addstr(row, col, s, *args)
        
def _addstr_centered(window, row, col, s, *args):
    col -= len(s) // 2
    if col < 0:
        s = s[-col:]
        col = 0
    window.addstr(row, col, s, *args)

################################################################################
