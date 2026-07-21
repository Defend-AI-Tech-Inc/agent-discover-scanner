from crewai import Agent, Task, Crew

MODEL_NAME = "gpt-4-turbo"

researcher = Agent(
    role="Researcher",
    goal="Research topics thoroughly",
    backstory="Expert researcher",
    allow_code_execution=False,
    model=MODEL_NAME,
)

task = Task(description="Research AI security", agent=researcher)
crew = Crew(agents=[researcher], tasks=[task])


def run():
    return crew.kickoff()
