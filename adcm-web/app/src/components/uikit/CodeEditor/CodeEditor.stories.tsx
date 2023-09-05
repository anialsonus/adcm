/* eslint-disable spellcheck/spell-checker */
import { useState } from 'react';
import CodeEditor from './CodeEditor';
import { Meta, StoryObj } from '@storybook/react';

type Story = StoryObj<typeof CodeEditor>;

const jsonText = `
{
  some_object: {
    some_string: "lorem ipsum",
    some_number: 123,
    some_boolean: true,
  },
  some_array: [{
    f1: 123,
    f2: "qwert",
  }, {
    f1: 456,
    f2: "asdfg",
  }],
}
`;

export default {
  title: 'uikit/CodeEditor',
  component: CodeEditor,
  argTypes: {
    language: {
      description: 'highlighter language',
      defaultValue: 'json',
    },
  },
} as Meta<typeof CodeEditor>;

const CodeEditorExample = ({ ...args }) => {
  const [code, setCode] = useState(args.code);
  return <CodeEditor code={code} language={args.language} setCode={setCode} />;
};

export const CodeEditorStory: Story = {
  args: {
    language: 'json',
    code: jsonText,
  },
  render: (args) => {
    return <CodeEditorExample {...args} />;
  },
};
