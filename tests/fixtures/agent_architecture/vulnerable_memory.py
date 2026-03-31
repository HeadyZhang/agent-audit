from langchain.memory import ConversationBufferMemory

memory = ConversationBufferMemory()

def handle_request(user_input):
    response = chain.run(input=user_input, memory=memory)
    return response
