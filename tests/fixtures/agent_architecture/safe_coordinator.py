from autogen import GroupChat, GroupChatManager

chat = GroupChat(
    agents=agents,
    allowed_or_disallowed_speaker_transitions={a: [b] for a, b in pairs},
    speaker_transitions_type="allowed"
)
