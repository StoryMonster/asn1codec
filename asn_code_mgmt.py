import re
from utils import reformat_asn_line

class AsnCodeMgmt(object):
    def __init__(self, data):
        self.lines = data.split('\n')
        self.msgs_with_definition = {}
        self._reformat_and_store_as_msgs_with_definition(data)
    
    def _reformat_and_store_as_msgs_with_definition(self, data):
        lines = data.split('\n')
        line_counter = 0
        macros = []
        macro_regular = re.compile(r"\s*([\w\-]+)\s+\w+\s+::=\s*([\w\-]+)\s*")
        asn_type_regular = re.compile(r"\s*([\w\-]+)\s*::=.*")
        bracket_counts = 0
        code_block = ''     ## save entire message definition in one line
        for line in lines:
            line_counter += 1
            if line.strip() == '': continue        ## ignore empty lines
            line = self._remove_comments(line)     ## remove comments in line and remove extra blank
            ## to check if it's a macro, if so save it in macros
            matched = macro_regular.match(line)
            if matched:
                macros.append((matched.group(1), matched.group(2)))
                continue
            ## to collect every asn message
            bracket_counts += (line.count('{') - line.count('}'))
            if bracket_counts > 0:
                code_block += line
            elif bracket_counts == 0:
                code_block += line
                matched = asn_type_regular.match(code_block)
                if matched:
                    self.msgs_with_definition[matched.group(1)] = code_block
                code_block = ''
            else:
                raise AsnCodeError("Error: line %d, unmatched }" % line_counter)
        if bracket_counts != 0:
            raise AsnCodeError("Error: unmatched {")
        ## to replace macros in all messages
        for msg in self.msgs_with_definition:
            for macro in macros:
                if macro[0] not in self.msgs_with_definition[msg]: continue
                replace_pattern = r"([^\w\-]+)({})([^\w\-]+)".format(macro[0])
                self.msgs_with_definition[msg] = re.sub(replace_pattern, r"\1 %s \3" % macro[1], self.msgs_with_definition[msg])

    def _remove_comments(self, line):
        patterns_of_comments = [(r"(.*)--.*--(.*)", "type1"), (r"(.*)?--.*", "type2")]
        for pattern in patterns_of_comments:
            matched = re.match(pattern[0], line)
            if matched:
                line = (matched.group(1) + " " + matched.group(2)) if pattern[1] == "type1" else matched.group(1)
                break
        return ' '.join(line.split())

    def get_message_definition(self, msg_name):
        from queue import Queue
        checked_msgs = []        # to avoid get one message definition multi times
        msgs = Queue()
        msgs.put(msg_name)
        res = ''
        while not msgs.empty():
            msg = msgs.get()
            if msg in checked_msgs: continue
            definition = self.msgs_with_definition[msg]
            res = res + "\n" + reformat_asn_line(definition)
            types = self._get_member_types(msg)
            checked_msgs.append(msg)
            for item in types:
                msgs.put(item)
        return res
    
    def _get_member_types(self, msg_name):
        definition = self.msgs_with_definition[msg_name]
        asn_key_words = ["SEQUENCE", "OF", "CHOICE", "BOOLEAN", "BIT", "STRING", "OCTET", "CONTAINING", "NULL", "SIZE",
                         "SET", "INTEGER", "DEFINITIONS", "AUTOMATIC", "TAGS", "BEGIN", "END", "IMPORTS", "FROM"]
        types = []
        for typ in re.findall(r"[\w\-]+", definition)[1:]:
            if (typ not in asn_key_words) and (typ in self.msgs_with_definition):
                types.append(typ)
        return types
