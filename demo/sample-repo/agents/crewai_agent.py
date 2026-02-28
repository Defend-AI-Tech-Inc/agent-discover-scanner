from crewai import Agent, Task, Crew

researcher = Agent(
    role="Researcher",
    goal="Research topics thoroughly",
    backstory="Expert researcher",
    allow_code_execution=False
)

task = Task(description="Research AI security", agent=researcher)
crew = Crew(agents=[researcher], tasks=[task])


def run():
    return crew.kickoff()
