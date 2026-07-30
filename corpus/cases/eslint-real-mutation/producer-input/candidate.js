// Controlled mutation: insert one source line.
function compare(userInput, expected) {
  if (userInput == expected) {
    return eval(userInput);
  }

  return null;
}

compare("1", "1");
