import pygame
import sys
import random
import time

# Game Constants
SCREEN_WIDTH = 800
SCREEN_HEIGHT = 600
BACKGROUND_COLOR = (0, 0, 0)
SNAKE_COLOR = (0, 255, 0)
FOOD_COLOR = (255, 0, 0)

class SnakeGame:
    def __init__(self):  # Corrected the __init__ method name
        pygame.init()
        self.screen = pygame.display.set_mode((SCREEN_WIDTH, SCREEN_HEIGHT))
        pygame.display.set_caption("Snake Game")
        self.clock = pygame.time.Clock()
        self.SCORE_FONT = pygame.font.SysFont("Arial", 24)  # Moved here
        self.reset_game()

    def reset_game(self):
        self.snake = [(200, 200), (220, 200), (240, 200)]
        self.food = self.generate_food()
        self.direction = "RIGHT"
        self.score = 0

    def generate_food(self):
        while True:
            x = random.randint(0, SCREEN_WIDTH - 20) // 20 * 20
            y = random.randint(0, SCREEN_HEIGHT - 20) // 20 * 20
            food = (x, y)
            if food not in self.snake:
                return food

    def draw_everything(self):
        self.screen.fill(BACKGROUND_COLOR)
        for x, y in self.snake:
            pygame.draw.rect(self.screen, SNAKE_COLOR, (x, y, 20, 20))
        pygame.draw.rect(self.screen, FOOD_COLOR, (*self.food, 20, 20))
        score_text = self.SCORE_FONT.render(f"Score: {self.score}", True, (255, 255, 255))
        self.screen.blit(score_text, (10, 10))
        pygame.display.update()

    def handle_events(self):
        for event in pygame.event.get():
            if event.type == pygame.QUIT:
                pygame.quit()
                sys.exit()
            elif event.type == pygame.KEYDOWN:
                if event.key == pygame.K_UP and self.direction != "DOWN":
                    self.direction = "UP"
                elif event.key == pygame.K_DOWN and self.direction != "UP":
                    self.direction = "DOWN"
                elif event.key == pygame.K_LEFT and self.direction != "RIGHT":
                    self.direction = "LEFT"
                elif event.key == pygame.K_RIGHT and self.direction != "LEFT":
                    self.direction = "RIGHT"

    def update_game_state(self):
        head = self.snake[-1]
        if self.direction == "UP":
            new_head = (head[0], head[1] - 20)
        elif self.direction == "DOWN":
            new_head = (head[0], head[1] + 20)
        elif self.direction == "LEFT":
            new_head = (head[0] - 20, head[1])
        elif self.direction == "RIGHT":
            new_head = (head[0] + 20, head[1])

        self.snake.append(new_head)

        if self.snake[-1] == self.food:
            self.score += 1
            self.food = self.generate_food()
        else:
            self.snake.pop(0)

        if (self.snake[-1][0] < 0 or self.snake[-1][0] >= SCREEN_WIDTH or
            self.snake[-1][1] < 0 or self.snake[-1][1] >= SCREEN_HEIGHT or
            self.snake[-1] in self.snake[:-1]):
            self.reset_game()

    def run(self):
        while True:
            self.handle_events()
            self.update_game_state()
            self.draw_everything()
            self.clock.tick(10)  # 10 FPS

if __name__ == "__main__":
    game = SnakeGame()
    game.run()
