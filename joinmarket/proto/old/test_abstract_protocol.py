from abstract_protocol import AbstractNPartyProtocol

import pytest

class AbstractProtoTest(AbstractNPartyProtocol):
    def __init__(self, role):
        self.role = role
        self.current_event = {} #default for "None" will be created
        self.event_history = {}            
        self.events = {
    -3: ["TEST_STATELESS_1", True, False],
    -2: ['TEST_STATELESS_2', True, False], 
    -1: ['TEST_STATELESS_3', True, False],
    0: ['TEST_STATEFUL_1', True, True],
    1: ['TEST_STATEFUL_ERROR_1', True, True],
    2: ['TEST_STATEFUL_SEND', True, True],
    3: ['TEST_STATEFUL_END', False, True]}
        self.error_events = [1]
    
    def get_sending_events(self):
        #should depend on role
        if self.role == "TEST":
            return [2]
    
    def get_initial_event(self):
        return 0

    def process_error(self, event, nick):
        print("Received error for event, nick: " + str([event, nick]))

    def msg_send(self, event, msgargs):
        print("Sending: " + str(msgargs))

def wrap_receive_event(tp, event, success=True, nick=None, msgargs=None):
        print("Receiving: " + str(event) + ", for nick: " + str(nick))
        res = tp.receive_event(event, nick=nick, msgargs=msgargs)
        if success:
            if not res[0]:
                print("Got error: " + str(res[1]))
            assert res[0]
        else:
            if len(res) > 1:
                print("Got expected error: " + str(res[1]))
            assert not res[0]

@pytest.mark.parametrize(
    "nick_sequences",
    [
        #Sequence of events for the default nick and for others
        ({None: [(-1, True,0), (2, True, 2), (2, True, 2),
                 (3, True, 3), (-1, True, 3)],
         "testnick1":[(1, False, 1),(3, False, 1)],
          "testnick2":[(-3, True, 0), (1, False, 1), (-2, True, 1)],
          "testnick3":[(0, True, 0), (-2, True, 0), (2, True, 2),
                       (3, True, 3), (3, False, 3)],
          "testnick4":[(2, True, 2), (0, False, 2)],
          }),
    ])
def test_abstract_protocol_multi(nick_sequences):
    tp = AbstractProtoTest("TEST")
    for i in range(max([len(x) for x in nick_sequences.values()])):
        for nick in nick_sequences.keys():
            if len(nick_sequences[nick]) < i+1:
                continue
            wrap_receive_event(tp, nick_sequences[nick][i][0],
                               nick_sequences[nick][i][1],
                               nick)
            assert tp.current_event[nick] == nick_sequences[nick][i][2]
    for nick in nick_sequences:
        print("Event history:")
        print(tp.event_history[nick])
        assert tp.event_history[nick] == [x[0] for x in nick_sequences[nick]]

def test_abstract_protocol_single():
    tp = AbstractProtoTest("TEST")
    #stateless can repeat and go in any order
    wrap_receive_event(tp, -2)
    assert tp.current_event[None] == 0
    wrap_receive_event(tp, -2)
    wrap_receive_event(tp, -3)
    wrap_receive_event(tp, -1)
    assert tp.current_event[None] == 0
    #normal flow
    wrap_receive_event(tp, 2)
    wrap_receive_event(tp, 3)
    #try to repeat un-allowed repeat
    wrap_receive_event(tp, 3, False)
    assert tp.current_event[None] == 3
    #stateless should still work
    wrap_receive_event(tp, -1)
    #restart
    tp = AbstractProtoTest("TEST")
    #do normal flow with allowed repeats
    for i in range(3):
        wrap_receive_event(tp, 2, success=True, msgargs=["foo", "bar"])
        assert tp.current_event[None] == 2
    wrap_receive_event(tp, 3)
    assert tp.current_event[None] == 3
    #try again but this time trigger explicit error and repeat error
    tp = AbstractProtoTest("TEST")
    wrap_receive_event(tp, 0, True)
    assert tp.current_event[None] == 0
    wrap_receive_event(tp, 1, False)
    assert tp.current_event[None] == 1
    wrap_receive_event(tp, -2)
    assert tp.current_event[None] == 1
    wrap_receive_event(tp, 2, False)
    assert tp.current_event[None] == 1
