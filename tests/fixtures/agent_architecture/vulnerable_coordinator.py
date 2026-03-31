from autogen import GroupChat, GroupChatManager

agents = [agent1, agent2, agent3]
chat = GroupChat(agents=agents, messages=[])
manager = GroupChatManager(groupchat=chat)
